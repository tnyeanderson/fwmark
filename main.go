/*
The fwmark CNI plugin allows setting a netfilter/iptables mark based on pod
annotations.

Add the fwmark plugin to the CNI chain after your main network provider
(flannel, calico, etc):

    {
      "type": "fwmark",
      "capabilities": {
         "io.kubernetes.cri.pod-annotations": true
      },
      "marks": {
         "vpn": {"mark": 16, "mask": 16}
      }
    }

The "16" decimal value mark and mask will be represented as "0x10/0x10" in
iptables. Add any other names and mark/mask configurations to the marks map to
have them available as annotation values.

Finally, add the following annotation to a pods and any traffic originating
from that pod will be marked:

    cni.fwmark.net/name: vpn

This will match with the "vpn" entry in the "marks" map from the CNI
configuration and set the corresponding iptables/netfilter mark using the
"mangle" table for any packets originating from the annotated pod.
*/
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"math"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
)

// Globals ------------------------------------------------------------

const PluginVersion = "v0.1.0"

// CommentPrefix is the text printed immediately before the container ID in the
// comment of iptables entries created by this plugin.
const CommentPrefix = "cni-fwmark-"

// AnnotationPrefix is the prefix/FQDN used in pod annotations which control
// this plugin.
const AnnotationPrefix = "cni.fwmark.net/"

// AnnotationKeys contains the keys for the pod annotations which control this
// plugin.
var AnnotationKeys = struct {
	Name string
}{
	Name: AnnotationPrefix + "name",
}

// Mark ---------------------------------------------------------------

type Mark struct {
	Mark uint32
	Mask uint32
}

// String returns a string representation of Mark as "mark/mask" in hexadecimal
// format. For example: "0x10/0x10" for decimal 16.
func (m *Mark) String() string {
	mask := m.Mask
	if mask == 0 {
		// Use default mask
		mask = math.MaxUint32
	}
	return fmt.Sprintf("0x%x/0x%x", m.Mark, mask)
}

// RuntimeConfig --------------------------------------------------------

// RuntimeConfig contains the PodAnnotations which have been included in the
// capabilities for this plugin.
type RuntimeConfig struct {
	PodAnnotations map[string]string `json:"io.kubernetes.cri.pod-annotations"`
}

// PluginConfig ---------------------------------------------------------

type PluginConfig struct {
	types.NetConf

	// prev is the concrete Result value for PrevResult
	prev *current.Result

	RuntimeConfig *RuntimeConfig

	// Marks is a map of names (derived from a pod annotation) to a corresponding
	// Mark.
	Marks map[string]Mark
}

// ContainerIP returns the IP of the container based on the previous plugin
// result.
//
// This function assumes that p.Init() has been called, which verifies that
// conf.PrevResult.IPs is not empty. It is subject to errors if this has not
// already been validated.
func (p *PluginConfig) ContainerIP() string {
	return p.prev.IPs[0].Address.IP.String()
}

// Mark returns the Mark derived from the pod annotation and the CNI config
func (p *PluginConfig) Mark() (*Mark, error) {
	name, ok := p.RuntimeConfig.PodAnnotations[AnnotationKeys.Name]
	if !ok {
		return nil, fmt.Errorf("annotation not found: %s", AnnotationKeys.Name)
	}
	mark, ok := p.Marks[name]
	if !ok {
		return nil, fmt.Errorf("mark name not found in CNI config: %s", name)
	}
	return &mark, nil
}

// PodHasAnnotation returns true if the pod has a fwmark annotation.
func (p *PluginConfig) PodHasAnnotation() bool {
	_, ok := p.RuntimeConfig.PodAnnotations[AnnotationKeys.Name]
	return ok
}

// ContainerID returns the Container ID based on CNI_CONTAINERID.
func (p *PluginConfig) ContainerID() string {
	return os.Getenv("CNI_CONTAINERID")
}

// Parse reads a PluginConfig from stdin and parses it into p.
func (p *PluginConfig) Parse(stdin []byte) error {
	if err := json.Unmarshal(stdin, p); err != nil {
		return fmt.Errorf("failed to parse network configuration: %v", err)
	}

	if err := version.ParsePrevResult(&p.NetConf); err != nil {
		return fmt.Errorf("could not parse prevResult: %v", err)
	}
	return nil
}

// Validate ensures the config is valid and converts it as needed, and
// returns any errors it encounters along the way.
func (p *PluginConfig) Validate() error {
	if p.NetConf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}

	// Convert the PrevResult to a concrete Result type that can be modified.
	prevResult, err := current.GetResult(p.NetConf.PrevResult)
	if err != nil {
		return fmt.Errorf("failed to convert prevResult: %v", err)
	}

	if len(prevResult.IPs) == 0 {
		return fmt.Errorf("got no container IPs")
	}

	p.prev = prevResult

	if p.ContainerID() == "" {
		return fmt.Errorf("container ID not found")
	}

	return nil
}

// Init parses and validates a PluginConfig.
//
// This is basically where all the plugin initialization happens.
func (p *PluginConfig) Init(stdin []byte) error {
	if err := p.Parse(stdin); err != nil {
		return err
	}

	return p.Validate()
}

// Functions ---------------------------------------------------------------

// buildRule returns a slice representing an iptables rule/command that is
// based on the provided arguments.
func buildRule(action, ip string, mark Mark, comment string) []string {
	src := fmt.Sprintf("%s/32", ip)
	return []string{action, "PREROUTING",
		"-t", "mangle",
		"-s", src,
		"-j", "MARK", "--set-mark", mark.String(),
		"-m", "comment", "--comment", comment,
	}
}

// lookupRulesByComment returns any existing iptables entries which contain the
// provided comment.
func lookupRulesByComment(comment string) ([]string, error) {
	rules := []string{}
	cmd := exec.Command("iptables", "-S", "-t", "mangle")
	out, err := cmd.Output()
	if err != nil {
		return rules, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		rule := scanner.Text()
		if strings.Contains(rule, fmt.Sprintf("%s", comment)) {
			rules = append(rules, rule)
		}
	}

	if err := scanner.Err(); err != nil {
		return rules, err
	}

	return rules, nil
}

// getComment returns the CommentPrefix followed by the value of
// CNI_CONTAINERID.
func getComment() string {
	return CommentPrefix + os.Getenv("CNI_CONTAINERID")
}

// run executes iptables with the provided arguments.
func run(args []string) error {
	cmd := exec.Command("iptables", args...)
	return cmd.Run()
}

// log prints the message to /tmp/fwmark-cni.log followed by a newline.
func log(message string) error {
	logger, err := os.Create("/tmp/fwmark-cni.log")
	if err != nil {
		return err
	}
	defer logger.Close()
	_, err = logger.WriteString(fmt.Sprintf("%s\n", message))
	return err
}

// Commands ---------------------------------------------------------------

// cmdAdd is executed when CNI_COMMAND=ADD.
func cmdAdd(args *skel.CmdArgs) error {
	conf := &PluginConfig{}
	err := conf.Init(args.StdinData)
	if err != nil {
		return err
	}

	// Do nothing if the pod has no fwmark annotation
	if !conf.PodHasAnnotation() {
		return types.PrintResult(conf.prev, conf.CNIVersion)
	}

	mark, err := conf.Mark()
	if err != nil {
		return err
	}

	action := "-A"
	rule := buildRule(action, conf.ContainerIP(), *mark, getComment())
	if err := run(rule); err != nil {
		return err
	}

	return types.PrintResult(conf.prev, conf.CNIVersion)
}

// cmdDel is executed when CNI_COMMAND=DEL.
func cmdDel(args *skel.CmdArgs) error {
	// IMPORTANT: The DELETE command runs the chain in reverse order, so there
	// will be no PrevResult! Hence the use of Parse instead of Init.

	conf := &PluginConfig{}
	err := conf.Parse(args.StdinData)
	if err != nil {
		return err
	}

	rules, err := lookupRulesByComment(getComment())
	if err != nil {
		return err
	}

	for _, rule := range rules {
		args := strings.Split(rule, " ")
		command := append([]string{"-D", "PREROUTING", "-t", "mangle"}, args[2:]...)
		if err := run(command); err != nil {
			return err
		}
	}

	// Avoid nil error in PrintResult if we are the first member in the chain.
	if conf.NetConf.PrevResult != nil {
		return types.PrintResult(conf.NetConf.PrevResult, conf.CNIVersion)
	}

	return nil
}

// cmdCheck is executed when CNI_COMMAND=CHECK.
func cmdCheck(args *skel.CmdArgs) error {
	conf := &PluginConfig{}
	err := conf.Init(args.StdinData)
	if err != nil {
		return err
	}

	// Do nothing if the pod has no fwmark annotation
	if !conf.PodHasAnnotation() {
		return types.PrintResult(conf.prev, conf.CNIVersion)
	}

	mark, err := conf.Mark()
	if err != nil {
		return err
	}

	action := "-C"
	rule := buildRule(action, conf.ContainerIP(), *mark, getComment())
	if err := run(rule); err != nil {
		return err
	}

	return types.PrintResult(conf.prev, conf.CNIVersion)
}

// main runs the corresponding CNI plugin command.
func main() {
	buildstr := fmt.Sprintf("CNI fwmark plugin %s", PluginVersion)
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, buildstr)
}
