package analyzers

import (
	"encoding/json"
	"testing"

	"inmetrics/eve/lexer"
	"inmetrics/eve/visitor"
)

func TestRunQueryForIAMRole(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("complex-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	query := lexer.Query{
		Context:  "Resources",
		Resource: "IAM.Role",
		Condition: lexer.Condition{
			LeftSide:  "AssumeRolePolicyDocument.Statement.Effect",
			Operator:  "==",
			RightSide: "Allow",
		},
		Message: "Found Wildcard permission in your IAM::Role nodes",
	}

	result, haveFound := RunQuery(query, template)

	if !haveFound || len(result.Findings) <= 0 {
		t.Fatal("Should have found something")
	}

	_, err = json.Marshal(result)

	if err != nil {
		t.Fatal(err)
	}

	if !haveFound || len(result.Findings) <= 0 {
		t.Fatal("Should have found something")
	}
}

func TestRunQueryEC2Subnet(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("complex-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	query := lexer.Query{
		Context:  "Resources",
		Resource: "EC2.Subnet",
		Condition: lexer.Condition{
			LeftSide:  "MapPublicIpOnLaunch",
			Operator:  "==",
			RightSide: "true",
		},
		Message: "Found public IP assignment for EC2 inside a Subnet",
	}

	result, haveFound := RunQuery(query, template)

	_, err = json.Marshal(result)

	if err != nil {
		t.Fatal(err)
	}

	if !haveFound || len(result.Findings) <= 0 {
		t.Fatal("Should have found something")
	}
}

func TestRunQueryBatchComputeEnvironment(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("complex-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	query := lexer.Query{
		Context:  "Resources",
		Resource: "Batch.ComputeEnvironment",
		Condition: lexer.Condition{
			LeftSide:  "ComputeResources.MaxvCpus",
			Operator:  ">",
			RightSide: "32",
		},
		Message: "Do not use more than 32 Max vCPUs in definition since we do not have that money.",
	}

	result, haveFound := RunQuery(query, template)

	_, err = json.Marshal(result)

	if err != nil {
		t.Fatal(err)
	}

	if !haveFound || len(result.Findings) <= 0 {
		t.Fatal("Should have found something")
	}
}

func TestRunQueryEC2SecurityGroupShoudlFindInWebSiteSample(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("websitesample-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	query := lexer.Query{
		Context:  "Resources",
		Resource: "EC2.SecurityGroup",
		Condition: lexer.Condition{
			LeftSide:  "SecurityGroupIngress.FromPort",
			Operator:  "==",
			RightSide: "22",
		},
		Message: "Found SSH service open in the default 22 port. Please consider using other port.",
	}

	result, haveFound := RunQuery(query, template)

	_, err = json.Marshal(result)

	if err != nil {
		t.Fatal(err)
	}

	if !haveFound || len(result.Findings) <= 0 {
		t.Fatal("Should have found something")
	}
}

func TestRunQueryEC2SecurityGroupShouldFindInChefTemplate(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("websitesample-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	query := lexer.Query{
		Context:  "Resources",
		Resource: "EC2.SecurityGroup",
		Condition: lexer.Condition{
			LeftSide:  "SecurityGroupIngress.FromPort",
			Operator:  "==",
			RightSide: "22",
		},
		Message: "Found SSH service open in the default 22 port. Please consider using other port.",
	}

	result, haveFound := RunQuery(query, template)

	_, err = json.Marshal(result)

	if err != nil {
		t.Fatal(err)
	}

	if !haveFound || len(result.Findings) <= 0 {
		t.Fatal("Should have found something")
	}
}

func TestRunQueryEC2SecurityGroupShouldFindInWebSiteTemplateWithDefaultRules(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("websitesample-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	queries, err := lexer.LoadIaCRules()

	if err != nil {
		t.Fatal(err)
	}

	results := RunQueries(template, queries)

	if len(results) <= 0 {
		t.Fatal("Should have found something")
	}
}

func TestRunQueryCloudFrontDistributionShouldFindInWebSiteTemplateWithCustomRule(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("websitesample-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	queries, err := lexer.ParseQuery(`
		ON Resources.CloudFront.Distribution
		IF DistributionConfig.Logging NOT EXISTS
		THEN "CloudFront Distribution should enable access logging"
		GO
	`)

	if err != nil {
		t.Fatal(err)
	}

	results := RunQueries(template, queries)

	if len(results) <= 0 {
		t.Fatal("Should have found something")
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			t.Log(finding.AffectedNode)
		}
	}
}

func TestRunQueryCodeBuildProjectShouldFindInWebSiteTemplateWithCustomRule(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("websitesample-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	queries, err := lexer.ParseQuery(`
		ON Resources.CodeBuild.Project
		IF EncryptionKey NOT EXISTS
		THEN "CodeBuild should specify a EncryptionKey value"
		GO
	`)

	if err != nil {
		t.Fatal(err)
	}

	results := RunQueries(template, queries)

	if len(results) <= 0 {
		t.Fatal("Should have found something")
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			t.Log(finding.AffectedNode)
		}
	}
}

func TestRunIAMRoleProjectShouldFindInComplexTemplateWithCustomRule(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("complex-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	queries, err := lexer.ParseQuery(`
		ON Resources.IAM.Role
		IF ManagedPolicyArns == "arn:aws:iam::aws:policy/AdministratorAccess"
		THEN "IAM role should not have AdministratorAccess policy"
		GO
	`)

	if err != nil {
		t.Fatal(err)
	}

	results := RunQueries(template, queries)

	if len(results) <= 0 {
		t.Fatal("Should have found something")
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			t.Log(finding.AffectedNode)
		}
	}
}

func TestRunIAMRoleProjectShouldFindInComplexTemplateWithCustomRule2(t *testing.T) {
	templateFilename := visitor.SolvePathToTestFolder("complex-template.json")
	template, err := visitor.ParseCloudFormationTemplate(templateFilename)

	if err != nil {
		t.Fatal(err)
	}

	queries, err := lexer.ParseQuery(`
		ON Resources.IAM.Role
		IF Statement.NotAction EXISTS
		THEN "IAM role should not allow Allow+NotAction"
		GO
	`)

	if err != nil {
		t.Fatal(err)
	}

	results := RunQueries(template, queries)

	if len(results) <= 0 {
		t.Fatal("Should have found something")
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			t.Log(finding.AffectedNode)
		}
	}
}
