package webmail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type MaildirService struct {
	vmailRoot string
	mtaHost   string
	mtaPort   int
	logger    *slog.Logger
}

func NewMaildirService(vmailRoot string, mtaHost string, mtaPort int, logger *slog.Logger) *MaildirService {
	if vmailRoot == "" {
		vmailRoot = "/var/vmail"
	}
	if mtaHost == "" {
		mtaHost = "127.0.0.1"
	}
	if mtaPort == 0 {
		mtaPort = 25
	}
	return &MaildirService{
		vmailRoot: vmailRoot,
		mtaHost:   mtaHost,
		mtaPort:   mtaPort,
		logger:    logger,
	}
}

func (s *MaildirService) getMaildirPath(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid email format")
	}
	localpart := parts[0]
	domain := parts[1]

	if strings.Contains(localpart, "..") || strings.Contains(domain, "..") ||
		strings.ContainsAny(localpart, "/\\") || strings.ContainsAny(domain, "/\\") {
		return "", fmt.Errorf("invalid mailbox path")
	}

	return filepath.Join(s.vmailRoot, domain, localpart, "Maildir"), nil
}

func (s *MaildirService) getFolderDir(maildirPath, folder string) (string, error) {
	folder = strings.TrimSpace(folder)
	if folder == "" || strings.EqualFold(folder, "inbox") {
		return maildirPath, nil
	}

	folderName := folder
	if !strings.HasPrefix(folderName, ".") {
		folderName = "." + folderName
	}

	// Prevent directory traversal
	cleanFolder := filepath.Clean(folderName)
	if strings.Contains(cleanFolder, "..") || strings.Contains(cleanFolder, "/") || strings.Contains(cleanFolder, "\\") {
		return "", fmt.Errorf("invalid folder name")
	}

	return filepath.Join(maildirPath, cleanFolder), nil
}

func (s *MaildirService) ensureFolders(maildirPath string) {
	standardFolders := []string{"", ".Sent", ".Drafts", ".Trash", ".Junk", ".Archive"}
	for _, f := range standardFolders {
		dir := filepath.Join(maildirPath, f)
		_ = os.MkdirAll(filepath.Join(dir, "cur"), 0750)
		_ = os.MkdirAll(filepath.Join(dir, "new"), 0750)
		_ = os.MkdirAll(filepath.Join(dir, "tmp"), 0750)
	}
}

func (s *MaildirService) ListFolders(ctx context.Context, email string) ([]Folder, error) {
	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return nil, err
	}

	s.ensureFolders(maildirPath)

	standardDefs := []struct {
		ID          string
		Name        string
		DisplayName string
		FolderDir   string
		Icon        string
	}{
		{ID: "inbox", Name: "INBOX", DisplayName: "Inbox", FolderDir: "", Icon: "inbox"},
		{ID: "sent", Name: "Sent", DisplayName: "Sent Mail", FolderDir: ".Sent", Icon: "send"},
		{ID: "drafts", Name: "Drafts", DisplayName: "Drafts", FolderDir: ".Drafts", Icon: "file-text"},
		{ID: "archive", Name: "Archive", DisplayName: "Archive", FolderDir: ".Archive", Icon: "archive"},
		{ID: "junk", Name: "Junk", DisplayName: "Junk / Spam", FolderDir: ".Junk", Icon: "alert-octagon"},
		{ID: "trash", Name: "Trash", DisplayName: "Trash", FolderDir: ".Trash", Icon: "trash-2"},
	}

	var result []Folder
	for _, def := range standardDefs {
		fPath := filepath.Join(maildirPath, def.FolderDir)
		total, unread := s.countMaildir(fPath)
		result = append(result, Folder{
			ID:          def.ID,
			Name:        def.Name,
			DisplayName: def.DisplayName,
			TotalCount:  total,
			UnreadCount: unread,
			Icon:        def.Icon,
		})
	}

	return result, nil
}

func (s *MaildirService) countMaildir(dir string) (int, int) {
	total := 0
	unread := 0

	for _, sub := range []string{"new", "cur"} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			total++
			if sub == "new" || !strings.Contains(e.Name(), ":2,") || !strings.Contains(e.Name(), "S") {
				unread++
			}
		}
	}
	return total, unread
}

type fileMeta struct {
	filename string
	subDir   string
	modTime  time.Time
	size     int64
	isRead   bool
}

func (s *MaildirService) ListMessages(ctx context.Context, email, folder string, page, limit int, search string) ([]MessageSummary, int, error) {
	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return nil, 0, err
	}

	s.ensureFolders(maildirPath)

	folderDir, err := s.getFolderDir(maildirPath, folder)
	if err != nil {
		return nil, 0, err
	}

	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 25
	}

	var files []fileMeta
	for _, sub := range []string{"new", "cur"} {
		dirPath := filepath.Join(folderDir, sub)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			isRead := sub == "cur" && strings.Contains(e.Name(), ":2,") && strings.Contains(e.Name(), "S")
			files = append(files, fileMeta{
				filename: e.Name(),
				subDir:   sub,
				modTime:  info.ModTime(),
				size:     info.Size(),
				isRead:   isRead,
			})
		}
	}

	// Sort by modification time desc
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	search = strings.ToLower(strings.TrimSpace(search))

	var filtered []MessageSummary
	for _, f := range files {
		filePath := filepath.Join(folderDir, f.subDir, f.filename)
		summary, err := s.parseMessageSummary(filePath, f.filename, folder, f.isRead, f.size, f.modTime)
		if err != nil {
			continue
		}

		if search != "" {
			match := strings.Contains(strings.ToLower(summary.Subject), search) ||
				strings.Contains(strings.ToLower(summary.From), search) ||
				strings.Contains(strings.ToLower(summary.Snippet), search)
			if !match {
				continue
			}
		}

		filtered = append(filtered, *summary)
	}

	total := len(filtered)
	start := (page - 1) * limit
	if start > total {
		return []MessageSummary{}, total, nil
	}
	end := start + limit
	if end > total {
		end = total
	}

	return filtered[start:end], total, nil
}

func (s *MaildirService) parseMessageSummary(filePath, filename, folder string, isRead bool, size int64, modTime time.Time) (*MessageSummary, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return &MessageSummary{
			ID:        filename,
			Folder:    folder,
			MessageID: filename,
			From:      "Unknown Sender",
			Subject:   "(Corrupted message)",
			Date:      modTime,
			IsRead:    isRead,
			Size:      size,
		}, nil
	}

	subject := decodeRFC2047(msg.Header.Get("Subject"))
	if subject == "" {
		subject = "(No Subject)"
	}

	from := decodeRFC2047(msg.Header.Get("From"))
	toHeader := decodeRFC2047(msg.Header.Get("To"))
	var to []string
	if toHeader != "" {
		to = []string{toHeader}
	}

	date, err := msg.Header.Date()
	if err != nil || date.IsZero() {
		date = modTime
	}

	snippet, hasAtt := extractSnippetAndAttachments(msg)

	return &MessageSummary{
		ID:             filename,
		Folder:         folder,
		MessageID:      msg.Header.Get("Message-ID"),
		From:           from,
		To:             to,
		Subject:        subject,
		Date:           date,
		IsRead:         isRead,
		HasAttachments: hasAtt,
		Size:           size,
		Snippet:        snippet,
	}, nil
}

func (s *MaildirService) GetMessage(ctx context.Context, email, folder, messageID string) (*MessageDetail, error) {
	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return nil, err
	}

	folderDir, err := s.getFolderDir(maildirPath, folder)
	if err != nil {
		return nil, err
	}

	filePath, subDir, err := s.findMessageFile(folderDir, messageID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	info, _ := os.Stat(filePath)
	modTime := time.Now()
	var size int64
	if info != nil {
		modTime = info.ModTime()
		size = info.Size()
	}

	date, err := msg.Header.Date()
	if err != nil || date.IsZero() {
		date = modTime
	}

	isRead := subDir == "cur" && strings.Contains(filepath.Base(filePath), ":2,") && strings.Contains(filepath.Base(filePath), "S")

	bodyText, bodyHTML, attachments := parseMIMEBody(msg)

	headers := make(map[string][]string)
	for k, v := range msg.Header {
		headers[k] = v
	}

	detail := &MessageDetail{
		MessageSummary: MessageSummary{
			ID:             filepath.Base(filePath),
			Folder:         folder,
			MessageID:      msg.Header.Get("Message-ID"),
			From:           decodeRFC2047(msg.Header.Get("From")),
			To:             splitAddresses(decodeRFC2047(msg.Header.Get("To"))),
			Subject:        decodeRFC2047(msg.Header.Get("Subject")),
			Date:           date,
			IsRead:         isRead,
			HasAttachments: len(attachments) > 0,
			Size:           size,
			Snippet:        createSnippet(bodyText, bodyHTML),
		},
		Cc:          splitAddresses(decodeRFC2047(msg.Header.Get("Cc"))),
		Bcc:         splitAddresses(decodeRFC2047(msg.Header.Get("Bcc"))),
		ReplyTo:     decodeRFC2047(msg.Header.Get("Reply-To")),
		BodyText:    bodyText,
		BodyHTML:    bodyHTML,
		Attachments: attachments,
		Headers:     headers,
	}

	// Auto mark as read upon fetching detail
	if !isRead {
		_ = s.MarkMessageRead(ctx, email, folder, filepath.Base(filePath), true)
	}

	return detail, nil
}

func (s *MaildirService) findMessageFile(folderDir, messageID string) (string, string, error) {
	if unescaped, err := url.PathUnescape(messageID); err == nil {
		messageID = unescaped
	}
	if unescaped, err := url.QueryUnescape(messageID); err == nil {
		messageID = unescaped
	}

	cleanID := filepath.Base(messageID)
	baseKey := cleanID
	if idx := strings.Index(cleanID, ":2,"); idx != -1 {
		baseKey = cleanID[:idx]
	}
	if idx := strings.Index(baseKey, ",U="); idx != -1 {
		baseKey = baseKey[:idx]
	}
	if idx := strings.Index(baseKey, ":"); idx != -1 {
		baseKey = baseKey[:idx]
	}

	for _, sub := range []string{"cur", "new"} {
		subPath := filepath.Join(folderDir, sub)
		// 1. Direct match with exact name
		p := filepath.Join(subPath, cleanID)
		if _, err := os.Stat(p); err == nil {
			return p, sub, nil
		}

		// 2. Scan directory
		entries, err := os.ReadDir(subPath)
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if name == cleanID || name == baseKey || strings.HasPrefix(name, baseKey) {
					return filepath.Join(subPath, name), sub, nil
				}
			}
		}
	}
	return "", "", fmt.Errorf("message not found")
}

func (s *MaildirService) MarkMessageRead(ctx context.Context, email, folder, messageID string, read bool) error {
	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return err
	}

	folderDir, err := s.getFolderDir(maildirPath, folder)
	if err != nil {
		return err
	}

	filePath, _, err := s.findMessageFile(folderDir, messageID)
	if err != nil {
		return err
	}

	base := filepath.Base(filePath)
	// Remove existing flag portion
	cleanName := base
	if idx := strings.Index(base, ":2,"); idx != -1 {
		cleanName = base[:idx]
	}

	curDir := filepath.Join(folderDir, "cur")
	var newPath string
	if read {
		newPath = filepath.Join(curDir, cleanName+":2,S")
	} else {
		newPath = filepath.Join(curDir, cleanName+":2,")
	}

	if filePath != newPath {
		_ = os.Rename(filePath, newPath)
	}
	return nil
}

func (s *MaildirService) MoveMessage(ctx context.Context, email, srcFolder, dstFolder, messageID string) error {
	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return err
	}

	srcDir, err := s.getFolderDir(maildirPath, srcFolder)
	if err != nil {
		return err
	}
	dstDir, err := s.getFolderDir(maildirPath, dstFolder)
	if err != nil {
		return err
	}

	srcFile, _, err := s.findMessageFile(srcDir, messageID)
	if err != nil {
		return err
	}

	dstCur := filepath.Join(dstDir, "cur")
	_ = os.MkdirAll(dstCur, 0750)

	dstFile := filepath.Join(dstCur, filepath.Base(srcFile))
	return os.Rename(srcFile, dstFile)
}

func (s *MaildirService) DeleteMessage(ctx context.Context, email, folder, messageID string) error {
	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return err
	}

	// If already in trash, permanent delete. Otherwise move to trash.
	if strings.EqualFold(folder, "trash") || strings.EqualFold(folder, ".trash") {
		folderDir, err := s.getFolderDir(maildirPath, folder)
		if err != nil {
			return err
		}
		fPath, _, err := s.findMessageFile(folderDir, messageID)
		if err != nil {
			return err
		}
		return os.Remove(fPath)
	}

	return s.MoveMessage(ctx, email, folder, "trash", messageID)
}

func (s *MaildirService) SendMessage(ctx context.Context, fromEmail string, req SendMessageRequest) (*MessageSummary, error) {
	if len(req.To) == 0 {
		return nil, fmt.Errorf("at least one recipient is required in 'to'")
	}

	// Build MIME message
	var buf bytes.Buffer
	boundary := fmt.Sprintf("=_OpenMail_%d_%s", time.Now().UnixNano(), randString(8))
	msgID := fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), randString(12), getDomainFromEmail(fromEmail))

	headers := make(map[string]string)
	headers["From"] = fromEmail
	headers["To"] = strings.Join(req.To, ", ")
	if len(req.Cc) > 0 {
		headers["Cc"] = strings.Join(req.Cc, ", ")
	}
	headers["Subject"] = encodeRFC2047(req.Subject)
	headers["Date"] = time.Now().Format(time.RFC1123Z)
	headers["Message-ID"] = msgID
	headers["MIME-Version"] = "1.0"
	headers["User-Agent"] = "OpenMail-Webmail/1.0"
	if req.InReplyTo != "" {
		headers["In-Reply-To"] = req.InReplyTo
	}
	if req.References != "" {
		headers["References"] = req.References
	}

	if len(req.Attachments) > 0 {
		headers["Content-Type"] = fmt.Sprintf("multipart/mixed; boundary=\"%s\"", boundary)
	} else if req.BodyHTML != "" && req.BodyText != "" {
		headers["Content-Type"] = fmt.Sprintf("multipart/alternative; boundary=\"%s\"", boundary)
	} else if req.BodyHTML != "" {
		headers["Content-Type"] = "text/html; charset=UTF-8"
		headers["Content-Transfer-Encoding"] = "quoted-printable"
	} else {
		headers["Content-Type"] = "text/plain; charset=UTF-8"
		headers["Content-Transfer-Encoding"] = "quoted-printable"
	}

	// Write headers
	for k, v := range headers {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	buf.WriteString("\r\n")

	// Write Body
	if len(req.Attachments) > 0 {
		writer := multipart.NewWriter(&buf)
		_ = writer.SetBoundary(boundary)

		// 1. Text/HTML alternative body
		altBoundary := fmt.Sprintf("=_OpenMail_Alt_%d_%s", time.Now().UnixNano(), randString(6))
		altHeader := make(textproto.MIMEHeader)
		altHeader.Set("Content-Type", fmt.Sprintf("multipart/alternative; boundary=\"%s\"", altBoundary))
		altPart, _ := writer.CreatePart(altHeader)

		altWriter := multipart.NewWriter(altPart)
		_ = altWriter.SetBoundary(altBoundary)

		if req.BodyText != "" {
			textHeader := make(textproto.MIMEHeader)
			textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
			textHeader.Set("Content-Transfer-Encoding", "quoted-printable")
			textP, _ := altWriter.CreatePart(textHeader)
			qp := quotedprintable.NewWriter(textP)
			_, _ = qp.Write([]byte(req.BodyText))
			_ = qp.Close()
		}

		if req.BodyHTML != "" {
			htmlHeader := make(textproto.MIMEHeader)
			htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
			htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")
			htmlP, _ := altWriter.CreatePart(htmlHeader)
			qp := quotedprintable.NewWriter(htmlP)
			_, _ = qp.Write([]byte(req.BodyHTML))
			_ = qp.Close()
		}
		_ = altWriter.Close()

		// 2. Attachments
		for _, att := range req.Attachments {
			attHeader := make(textproto.MIMEHeader)
			cType := att.ContentType
			if cType == "" {
				cType = "application/octet-stream"
			}
			attHeader.Set("Content-Type", fmt.Sprintf("%s; name=\"%s\"", cType, att.Filename))
			attHeader.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", att.Filename))
			attHeader.Set("Content-Transfer-Encoding", "base64")

			part, err := writer.CreatePart(attHeader)
			if err != nil {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(att.DataB64)
			if err != nil {
				continue
			}
			encoder := base64.NewEncoder(base64.StdEncoding, part)
			_, _ = encoder.Write(decoded)
			_ = encoder.Close()
		}
		_ = writer.Close()

	} else if req.BodyHTML != "" && req.BodyText != "" {
		writer := multipart.NewWriter(&buf)
		_ = writer.SetBoundary(boundary)

		textHeader := make(textproto.MIMEHeader)
		textHeader.Set("Content-Type", "text/plain; charset=UTF-8")
		textHeader.Set("Content-Transfer-Encoding", "quoted-printable")
		textP, _ := writer.CreatePart(textHeader)
		qpText := quotedprintable.NewWriter(textP)
		_, _ = qpText.Write([]byte(req.BodyText))
		_ = qpText.Close()

		htmlHeader := make(textproto.MIMEHeader)
		htmlHeader.Set("Content-Type", "text/html; charset=UTF-8")
		htmlHeader.Set("Content-Transfer-Encoding", "quoted-printable")
		htmlP, _ := writer.CreatePart(htmlHeader)
		qpHtml := quotedprintable.NewWriter(htmlP)
		_, _ = qpHtml.Write([]byte(req.BodyHTML))
		_ = qpHtml.Close()

		_ = writer.Close()
	} else {
		content := req.BodyText
		if content == "" {
			content = req.BodyHTML
		}
		qp := quotedprintable.NewWriter(&buf)
		_, _ = qp.Write([]byte(content))
		_ = qp.Close()
	}

	rawBytes := buf.Bytes()

	// 1. Deliver to local Postfix MTA
	allRecipients := append(append([]string{}, req.To...), req.Cc...)
	allRecipients = append(allRecipients, req.Bcc...)

	mtaAddr := fmt.Sprintf("%s:%d", s.mtaHost, s.mtaPort)
	if err := sendRawSMTP(mtaAddr, fromEmail, allRecipients, rawBytes); err != nil {
		// Fallback to localhost:25 or postfix:25
		if err2 := sendRawSMTP("postfix:25", fromEmail, allRecipients, rawBytes); err2 != nil {
			if err3 := sendRawSMTP("127.0.0.1:25", fromEmail, allRecipients, rawBytes); err3 != nil {
				return nil, fmt.Errorf("failed to submit email to Postfix MTA: %w", err)
			}
		}
	}

	// 2. Save a copy into .Sent folder of sender
	maildirPath, err := s.getMaildirPath(fromEmail)
	if err == nil {
		sentCur := filepath.Join(maildirPath, ".Sent", "cur")
		_ = os.MkdirAll(sentCur, 0750)
		sentFileName := fmt.Sprintf("%d.%s_openmail:2,S", time.Now().Unix(), randString(10))
		_ = os.WriteFile(filepath.Join(sentCur, sentFileName), rawBytes, 0640)
	}

	return &MessageSummary{
		ID:        msgID,
		Folder:    "sent",
		MessageID: msgID,
		From:      fromEmail,
		To:        req.To,
		Subject:   req.Subject,
		Date:      time.Now(),
		IsRead:    true,
		Size:      int64(len(rawBytes)),
		Snippet:   createSnippet(req.BodyText, req.BodyHTML),
	}, nil
}

func (s *MaildirService) GetAttachment(ctx context.Context, email, folder, messageID, attachmentID string) (string, string, []byte, error) {
	detail, err := s.GetMessage(ctx, email, folder, messageID)
	if err != nil {
		return "", "", nil, err
	}

	maildirPath, err := s.getMaildirPath(email)
	if err != nil {
		return "", "", nil, err
	}

	folderDir, err := s.getFolderDir(maildirPath, folder)
	if err != nil {
		return "", "", nil, err
	}

	filePath, _, err := s.findMessageFile(folderDir, messageID)
	if err != nil {
		return "", "", nil, err
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", "", nil, err
	}

	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return "", "", nil, err
	}

	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		idx := 0
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
			idx++
			attID := fmt.Sprintf("att-%d", idx)
			filename := p.FileName()
			if filename == "" {
				filename = fmt.Sprintf("attachment-%d", idx)
			}
			if attID == attachmentID || filename == attachmentID {
				content, _ := io.ReadAll(p)
				return filename, p.Header.Get("Content-Type"), content, nil
			}
		}
	}

	for _, att := range detail.Attachments {
		if att.ID == attachmentID {
			return att.Filename, att.ContentType, nil, nil
		}
	}

	return "", "", nil, fmt.Errorf("attachment not found")
}

// Helpers
func sendRawSMTP(addr, from string, recipients []string, body []byte) error {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, "localhost")
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Close()
}

func parseMIMEBody(msg *mail.Message) (string, string, []Attachment) {
	cType := msg.Header.Get("Content-Type")
	if cType == "" {
		cType = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(cType)
	if err != nil {
		b, _ := io.ReadAll(msg.Body)
		return string(b), "", nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		return parseMultipart(msg.Body, params["boundary"])
	}

	bodyBytes, _ := io.ReadAll(msg.Body)
	encoding := strings.ToLower(msg.Header.Get("Content-Transfer-Encoding"))
	decoded := decodeContent(bodyBytes, encoding)

	if strings.HasPrefix(mediaType, "text/html") {
		return "", string(decoded), nil
	}
	return string(decoded), "", nil
}

func parseMultipart(r io.Reader, boundary string) (string, string, []Attachment) {
	var bodyText, bodyHTML string
	var attachments []Attachment

	mr := multipart.NewReader(r, boundary)
	idx := 0
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		idx++

		pType := p.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(pType)
		if err != nil {
			mediaType = "application/octet-stream"
		}

		if strings.HasPrefix(mediaType, "multipart/") {
			subText, subHTML, subAtt := parseMultipart(p, params["boundary"])
			if bodyText == "" {
				bodyText = subText
			}
			if bodyHTML == "" {
				bodyHTML = subHTML
			}
			attachments = append(attachments, subAtt...)
			continue
		}

		filename := p.FileName()
		disp, _, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))

		isAttachment := filename != "" || disp == "attachment"

		partBytes, _ := io.ReadAll(p)
		encoding := strings.ToLower(p.Header.Get("Content-Transfer-Encoding"))
		decoded := decodeContent(partBytes, encoding)

		if isAttachment {
			if filename == "" {
				filename = fmt.Sprintf("attachment-%d", idx)
			}
			attachments = append(attachments, Attachment{
				ID:          fmt.Sprintf("att-%d", idx),
				Filename:    decodeRFC2047(filename),
				ContentType: mediaType,
				Size:        int64(len(decoded)),
				ContentID:   p.Header.Get("Content-ID"),
			})
		} else if strings.HasPrefix(mediaType, "text/html") {
			bodyHTML = string(decoded)
		} else if strings.HasPrefix(mediaType, "text/plain") {
			bodyText = string(decoded)
		} else {
			attachments = append(attachments, Attachment{
				ID:          fmt.Sprintf("att-%d", idx),
				Filename:    fmt.Sprintf("part-%d", idx),
				ContentType: mediaType,
				Size:        int64(len(decoded)),
			})
		}
	}

	return bodyText, bodyHTML, attachments
}

func extractSnippetAndAttachments(msg *mail.Message) (string, bool) {
	cType := msg.Header.Get("Content-Type")
	if cType == "" {
		b, _ := io.ReadAll(io.LimitReader(msg.Body, 512))
		return cleanSnippet(string(b)), false
	}
	mediaType, params, err := mime.ParseMediaType(cType)
	if err != nil {
		b, _ := io.ReadAll(io.LimitReader(msg.Body, 512))
		return cleanSnippet(string(b)), false
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		text, html, atts := parseMultipart(msg.Body, params["boundary"])
		return createSnippet(text, html), len(atts) > 0
	}
	b, _ := io.ReadAll(io.LimitReader(msg.Body, 512))
	encoding := strings.ToLower(msg.Header.Get("Content-Transfer-Encoding"))
	decoded := decodeContent(b, encoding)
	return cleanSnippet(string(decoded)), false
}

func decodeContent(data []byte, encoding string) []byte {
	switch encoding {
	case "base64":
		cleaned := strings.Map(func(r rune) rune {
			if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", r) {
				return r
			}
			return -1
		}, string(data))
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err == nil {
			return decoded
		}
	case "quoted-printable":
		r := quotedprintable.NewReader(bytes.NewReader(data))
		decoded, err := io.ReadAll(r)
		if err == nil {
			return decoded
		}
	}
	return data
}

func decodeRFC2047(s string) string {
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(s)
	if err == nil {
		return decoded
	}
	return s
}

func encodeRFC2047(s string) string {
	if isASCII(s) {
		return s
	}
	return mime.BEncoding.Encode("UTF-8", s)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

func splitAddresses(header string) []string {
	if header == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(header)
	if err == nil {
		var res []string
		for _, a := range addrs {
			res = append(res, a.String())
		}
		return res
	}
	parts := strings.Split(header, ",")
	var res []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			res = append(res, t)
		}
	}
	return res
}

func createSnippet(text, html string) string {
	if text != "" {
		return cleanSnippet(text)
	}
	if html != "" {
		// Strip basic html tags
		stripped := stripHTML(html)
		return cleanSnippet(stripped)
	}
	return ""
}

func cleanSnippet(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	words := strings.Fields(s)
	joined := strings.Join(words, " ")
	if len(joined) > 160 {
		return joined[:160] + "..."
	}
	return joined
}

func stripHTML(s string) string {
	var buf bytes.Buffer
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			buf.WriteRune(' ')
			continue
		}
		if !inTag {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func randString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)[:n]
}

func getDomainFromEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		return parts[1]
	}
	return "localhost"
}
