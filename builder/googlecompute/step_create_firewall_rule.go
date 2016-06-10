package googlecompute

import (
	"errors"
	"fmt"
	"time"

	"github.com/mitchellh/multistep"
	"github.com/mitchellh/packer/packer"
	"google.golang.org/api/compute/v1"
)

// StepCreateFirewallRule represents a Packer build step that generates SSH key pairs.
type StepCreateFirewallRule struct {
	Debug        bool
}

// Run executes the Packer build step that generates SSH key pairs.
func (s *StepCreateFirewallRule) Run(state multistep.StateBag) multistep.StepAction {
	config := state.Get("config").(*Config)
	driver := state.Get("driver").(Driver)
	ui := state.Get("ui").(packer.Ui)

	ui.Say("Creating a packer filewall rule...")
	name := fmt.Sprintf("%s-temporary-packer", config.InstanceName)

	errCh, err := driver.CreateFirewallRule(&FirewallRule{
		Allowed: &compute.FirewallAllowed{
			IPProtocol: "tcp",
			Ports: []string{"22"},
		},
		Description: "New temporary firewall rule created by Packer",
		Name: name,
		Network: config.Network,
		SourceRanges: []string{"0.0.0.0/0"},
		TargetTags: config.Tags,
	})

	if err == nil {
		ui.Message("Waiting for creation operation to complete...")
		select {
		case err = <-errCh:
		case <-time.After(config.stateTimeout):
			err = errors.New("time out while waiting for firewall rule to create")
		}
	}

	if err != nil {
		err := fmt.Errorf("Error creating firewall rule: %s", err)
		state.Put("error", err)
		ui.Error(err.Error())
		return multistep.ActionHalt
	}

	ui.Message("Firewall rule has been created!")

	if s.Debug {
		if name != "" {
			ui.Message(fmt.Sprintf("Firewall rule: %s created", name))
		}
	}

	// Things succeeded, store the name so we can remove it later
	state.Put("firewall_rule_name", name)

	return multistep.ActionContinue
}

// Remove temporoary firewall rule
func (s *StepCreateFirewallRule) Cleanup(state multistep.StateBag) {
	nameRaw, ok := state.GetOk("firewall_rule_name")
	if !ok {
		return
	}
	name := nameRaw.(string)
	if name == "" {
		return
	}

	config := state.Get("config").(*Config)
	driver := state.Get("driver").(Driver)
	ui := state.Get("ui").(packer.Ui)

	ui.Say("Deleting fireall rule...")
	errCh, err := driver.DeleteFirewallRule(name)

	if err == nil {
		select {
		case err = <-errCh:
		case <-time.After(config.stateTimeout):
			err = errors.New("time out while waiting for firewall rule to delete")
		}
	}

	if err != nil {
		ui.Error(fmt.Sprintf(
			"Error deleting firewall rule. Please delete it manually.\n\n"+
				"Name: %s\n"+
				"Error: %s", name, err))
	}

	ui.Message("Firewall rule has been deleted!")
	state.Put("firewall_rule_name", "")

	return
}
