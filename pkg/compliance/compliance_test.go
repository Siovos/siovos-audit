package compliance_test

import (
	"testing"

	"github.com/Siovos/siovos-audit/pkg/compliance"
)

func TestFrameworks_Exist(t *testing.T) {
	if _, ok := compliance.Frameworks["cis-level1"]; !ok {
		t.Error("cis-level1 framework should exist")
	}
	if _, ok := compliance.Frameworks["soc2-basic"]; !ok {
		t.Error("soc2-basic framework should exist")
	}
}

func TestCISLevel1_HasControls(t *testing.T) {
	cis := compliance.Frameworks["cis-level1"]
	if len(cis.Controls) < 20 {
		t.Errorf("CIS should have 20+ controls, got %d", len(cis.Controls))
	}
	for _, ctrl := range cis.Controls {
		if ctrl.ID == "" || ctrl.Name == "" {
			t.Error("every control must have ID and Name")
		}
		if len(ctrl.FindingIDs) == 0 {
			t.Errorf("control %s has no finding IDs", ctrl.ID)
		}
	}
}

func TestSOC2_HasControls(t *testing.T) {
	soc2 := compliance.Frameworks["soc2-basic"]
	if len(soc2.Controls) < 5 {
		t.Errorf("SOC2 should have 5+ controls, got %d", len(soc2.Controls))
	}
}

func TestFrameworkList(t *testing.T) {
	list := compliance.FrameworkList()
	if len(list) != 2 {
		t.Errorf("expected 2 frameworks, got %d", len(list))
	}
}
