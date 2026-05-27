// Package judge 把 detector 的 severity 映射成具体动作。
package judge

import (
	"github.com/example/subgw/internal/config"
	"github.com/example/subgw/internal/detector"
)

type Action string

const (
	ActPass Action = "pass"
	ActSlow Action = "slow"
	ActFake Action = "fake"
	ActDeny Action = "deny"
)

type Decision struct {
	Action Action
	Reason string
}

func Decide(cfg *config.Config, res detector.Result) Decision {
	if cfg.Detector.ObserveOnly {
		return Decision{Action: ActPass, Reason: "observe_only"}
	}
	switch res.Severity {
	case detector.SevYellow:
		return Decision{Action: Action(cfg.Actions.Yellow), Reason: "yellow:" + res.Note}
	case detector.SevOrange:
		return Decision{Action: Action(cfg.Actions.Orange), Reason: "orange:" + res.Note}
	case detector.SevRed:
		return Decision{Action: Action(cfg.Actions.Red), Reason: "red:" + res.Note}
	}
	return Decision{Action: ActPass}
}
