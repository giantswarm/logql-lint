package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/fatih/color"
	"github.com/grafana/loki/v3/pkg/logql/syntax"
	monitoringv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	ExitSuccess = 0
	ExitError   = 1
)

// Config holds the validation configuration
type Config struct {
	MandatoryLabels []string
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		MandatoryLabels: []string{"cluster_id", "installation"},
	}
}

// SimpleRuleGroup represents a rule group for plain YAML parsing.
// We need this because prometheus-operator's RuleGroup uses intstr.IntOrString
// for the Expr field, which doesn't unmarshal properly from plain YAML files
// with multiline strings. This type is only used for non-CRD rule files.
type SimpleRuleGroup struct {
	Name  string       `yaml:"name"`
	Rules []SimpleRule `yaml:"rules"`
}

// SimpleRule represents a single rule for plain YAML parsing.
// This uses a plain string for Expr instead of intstr.IntOrString,
// allowing proper unmarshaling from plain YAML rule files.
type SimpleRule struct {
	Alert       string            `yaml:"alert,omitempty"`
	Record      string            `yaml:"record,omitempty"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
}

// ValidationError represents a validation issue
type ValidationError struct {
	File        string
	Group       string
	Rule        string
	Type        string
	Message     string
	Aggregation string
}

// Validator handles validation logic
type Validator struct {
	config *Config
	errors []ValidationError
}

// NewValidator creates a new validator
func NewValidator(config *Config) *Validator {
	return &Validator{
		config: config,
		errors: []ValidationError{},
	}
}

var (
	mandatoryLabels []string
	verbose         bool
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "logql-lint [files...]",
		Short: "LogQL Aggregation Label Checker",
		Long: `Validates that LogQL aggregations preserve mandatory labels.

This tool checks PrometheusRule files (or rule group YAML files) to ensure
that all aggregation operations preserve the specified mandatory labels.`,
		Example: `  # Check a single file
  logql-lint rules.yml

  # Check multiple files
  logql-lint rules1.yml rules2.yml

  # Check all .logs.yml files
  logql-lint '**/*.logs.yml'

  # Custom mandatory labels
  logql-lint --labels cluster_id,installation,region rules.yml

  # Verbose output
  logql-lint -v rules.yml`,
		Args: cobra.MinimumNArgs(1),
		RunE: runValidation,
	}

	rootCmd.Flags().StringSliceVarP(&mandatoryLabels, "labels", "l", []string{"cluster_id", "installation"},
		"Mandatory labels that must be preserved in aggregations")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false,
		"Verbose output")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(ExitError)
	}
}

func runValidation(cmd *cobra.Command, args []string) error {
	// Create config
	config := &Config{
		MandatoryLabels: mandatoryLabels,
	}

	validator := NewValidator(config)

	// Print header
	printHeader(config)

	// Validate each file
	totalFiles := 0
	for _, pattern := range args {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid pattern %s: %v\n", pattern, err)
			continue
		}

		for _, file := range matches {
			if verbose {
				fmt.Printf("Checking: %s\n", file)
			}
			if err := validator.ValidateFile(file); err != nil {
				fmt.Fprintf(os.Stderr, "Error validating %s: %v\n", file, err)
			}
			totalFiles++
		}
	}

	// Print results
	printResults(validator.errors, totalFiles)

	if len(validator.errors) > 0 {
		os.Exit(ExitError)
	}

	return nil
}

// ValidateFile validates a single rule file
func (v *Validator) ValidateFile(filepath string) error {
	// Read file
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as PrometheusRule CRD first (has apiVersion and kind)
	// These use the official prometheus-operator types
	var rule monitoringv1.PrometheusRule
	if err := yaml.Unmarshal(data, &rule); err == nil && rule.Kind == "PrometheusRule" {
		// It's a full CRD
		for _, group := range rule.Spec.Groups {
			for _, r := range group.Rules {
				ruleName := r.Alert
				if ruleName == "" {
					ruleName = r.Record
				}
				v.validateRule(filepath, group.Name, ruleName, r.Expr.String())
			}
		}
		return nil
	}

	// Try to parse as just a spec (groups only) - plain YAML rule files
	// We use SimpleRuleGroup here because prometheus-operator's types use
	// intstr.IntOrString which doesn't unmarshal properly from plain YAML
	var spec struct {
		Groups []SimpleRuleGroup `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate each rule group
	for _, group := range spec.Groups {
		for _, r := range group.Rules {
			ruleName := r.Alert
			if ruleName == "" {
				ruleName = r.Record
			}
			v.validateRule(filepath, group.Name, ruleName, r.Expr)
		}
	}

	return nil
}

// validateRule validates a single rule's expression
func (v *Validator) validateRule(file, group, ruleName, query string) {
	// Parse the LogQL query
	expr, err := syntax.ParseExpr(query)
	if err != nil {
		v.errors = append(v.errors, ValidationError{
			File:    file,
			Group:   group,
			Rule:    ruleName,
			Type:    "syntax_error",
			Message: fmt.Sprintf("Failed to parse query: %v", err),
		})
		return
	}

	// Walk the AST and check aggregations
	v.checkAggregations(file, group, ruleName, expr)
}

// checkAggregations walks the AST and validates aggregations
func (v *Validator) checkAggregations(file, group, ruleName string, expr syntax.Expr) {
	expr.Walk(func(e syntax.Expr) bool {
		if agg, ok := e.(*syntax.VectorAggregationExpr); ok {
			v.validateAggregation(file, group, ruleName, agg)
		}
		return true // Continue walking
	})
}

// validateAggregation checks if an aggregation preserves mandatory labels
func (v *Validator) validateAggregation(file, group, ruleName string, agg *syntax.VectorAggregationExpr) {
	op := agg.Operation
	grouping := agg.Grouping

	// Check if aggregation has grouping
	if grouping == nil {
		v.errors = append(v.errors, ValidationError{
			File:        file,
			Group:       group,
			Rule:        ruleName,
			Type:        "no_grouping",
			Message:     fmt.Sprintf("Aggregation '%s' has no label grouping - all labels will be lost", op),
			Aggregation: agg.String(),
		})
		return
	}

	// Check grouping type
	if grouping.Without {
		// Using 'without' - check that mandatory labels are not excluded
		for _, label := range grouping.Groups {
			if slices.Contains(v.config.MandatoryLabels, label) {
				v.errors = append(v.errors, ValidationError{
					File:        file,
					Group:       group,
					Rule:        ruleName,
					Type:        "excluded_label",
					Message:     fmt.Sprintf("Aggregation '%s' excludes mandatory label '%s' in 'without' clause", op, label),
					Aggregation: agg.String(),
				})
			}
		}
	} else {
		// Using 'by' - check that all mandatory labels are included
		for _, mandatoryLabel := range v.config.MandatoryLabels {
			if !slices.Contains(grouping.Groups, mandatoryLabel) {
				v.errors = append(v.errors, ValidationError{
					File:        file,
					Group:       group,
					Rule:        ruleName,
					Type:        "missing_label",
					Message:     fmt.Sprintf("Aggregation '%s' missing mandatory label '%s' in 'by' clause", op, mandatoryLabel),
					Aggregation: agg.String(),
				})
			}
		}
	}
}

// Helper functions

func printHeader(config *Config) {
	fmt.Println("==================================================")
	fmt.Println("LogQL Aggregation Label Checker")
	fmt.Println("==================================================")
	fmt.Println("Checking that aggregations preserve mandatory labels:")
	for _, label := range config.MandatoryLabels {
		fmt.Printf("  - %s\n", label)
	}
	fmt.Println("==================================================")
	fmt.Println()
}

func printResults(errors []ValidationError, totalFiles int) {
	fmt.Println("==================================================")
	fmt.Println("Summary")
	fmt.Println("==================================================")
	fmt.Printf("Files checked: %d\n", totalFiles)

	if len(errors) == 0 {
		green := color.New(color.FgGreen)
		green.Println("✓ All checks passed!")
		green.Println("✓ All aggregations preserve mandatory labels")
		return
	}

	// Group errors by file
	fileErrors := make(map[string][]ValidationError)
	for _, err := range errors {
		fileErrors[err.File] = append(fileErrors[err.File], err)
	}

	red := color.New(color.FgRed)
	red.Printf("✗ Found %d error(s) in %d file(s)\n\n", len(errors), len(fileErrors))

	// Print errors grouped by file
	redBold := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	
	for file, errs := range fileErrors {
		red.Print("✗ ")
		fmt.Println(file)
		for _, err := range errs {
			fmt.Printf("  Group: %s\n", err.Group)
			fmt.Printf("  Rule: %s\n", err.Rule)
			yellow.Print("  Aggregation: ")
			fmt.Println(err.Aggregation)
			redBold.Print("  Error: ")
			fmt.Println(err.Message)
			fmt.Println()
		}
	}

	fmt.Println("Please fix the aggregations to include all mandatory labels.")
}
