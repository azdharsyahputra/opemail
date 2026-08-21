package queue

import (
	"context"
	"fmt"
)

type CheckItem struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}

type DoctorReport struct {
	Healthy bool        `json:"healthy"`
	Checks  []CheckItem `json:"checks"`
}

func RunDoctor(ctx context.Context, s Service) *DoctorReport {
	report := &DoctorReport{Healthy: true}

	summary, err := s.GetStatus(ctx)
	if err != nil {
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Postfix Queue Access",
			Passed:  false,
			Message: fmt.Sprintf("Failed to query queue: %v", err),
		})
		report.Healthy = false
		return report
	}

	report.Checks = append(report.Checks, CheckItem{
		Name:    "Postfix Queue Access",
		Passed:  true,
		Message: fmt.Sprintf("%d messages in queue (Active: %d, Deferred: %d, Hold: %d)", summary.Total, summary.Active, summary.Deferred, summary.Hold),
	})

	if summary.Deferred > 100 {
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Deferred Queue Health",
			Passed:  false,
			Message: fmt.Sprintf("High deferred queue count: %d", summary.Deferred),
		})
		report.Healthy = false
	} else {
		report.Checks = append(report.Checks, CheckItem{
			Name:    "Deferred Queue Health",
			Passed:  true,
			Message: "Deferred count within normal threshold",
		})
	}

	return report
}
