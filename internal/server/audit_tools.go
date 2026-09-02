package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"ssh-mcp/internal/audit"
)

func (s *Service) registerAuditTools(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "audit-list", Description: "Read recent redacted events from the verified, hash-chained audit log.", Annotations: annotations(true, false)}, s.listAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "audit-verify", Description: "Verify every hash link in the append-only audit log.", Annotations: annotations(true, false)}, s.verifyAudit)
}

type auditListInput struct {
	Limit int `json:"limit,omitempty"`
}

type auditListOutput struct {
	Events []audit.Event `json:"events"`
}

func (s *Service) listAudit(_ context.Context, _ *mcp.CallToolRequest, input auditListInput) (*mcp.CallToolResult, auditListOutput, error) {
	if input.Limit < 0 || input.Limit > 1000 {
		return nil, auditListOutput{}, fmt.Errorf("limit must be between 1 and 1000 when specified")
	}
	events, err := s.audit.Read(input.Limit)
	if err != nil {
		return nil, auditListOutput{}, err
	}
	return nil, auditListOutput{Events: events}, nil
}

type auditVerifyOutput struct {
	Valid bool `json:"valid"`
}

func (s *Service) verifyAudit(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, auditVerifyOutput, error) {
	if err := s.audit.Verify(); err != nil {
		return nil, auditVerifyOutput{Valid: false}, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Audit chain is valid"}}}, auditVerifyOutput{Valid: true}, nil
}
