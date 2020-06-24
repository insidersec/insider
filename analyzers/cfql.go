package analyzers

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"insider/lexer"
)

/*
	How a CFQL query looks like:
		ON EC2.Subnet
		IF MapPublicIpOnLaunch == true
		THEN "You should not allow all the EC2 instances inside a Subnet get a public IP"
		GO
*/

var (
	validContexts = []string{
		"Outputs",
		"Metadata",
		"Mappings",
		"Resources",
		"Parameters",
		"Conditions",
	}

	// ErrorInvalidOperator is thrown when the engine do not found any valid operator
	// for the given Condition
	ErrorInvalidOperator = errors.New("invalid operator found")

	// ErrorInvalidResource is thrown when the engine do not found the given Resource
	ErrorInvalidResource = errors.New("invalid type found in Resources section")

	// ErrorInvalidContext is thrown when the engine do not found the given Context
	ErrorInvalidContext = errors.New("invalid Context")

	// ErrorEmptyContext is thrown when there is no data
	// following the map[string]interface{} interface
	// in the given Context section
	ErrorEmptyContext = errors.New("could not find any data within this Context")
)

func evalCondition(leftHand []string, rightHand string, operator string) (bool, error) {
	results := make([]bool, 0)
	var rightHandOperand string

	if lexer.IsExistsOperation(operator) {
		if operator == lexer.NotExistsOperator {
			return (len(leftHand) <= 0), nil
		}

		return !(len(leftHand) <= 0), nil
	}

	rightHandOperand = rightHand

	for _, operand := range leftHand {
		switch operator {
		case "==":
			results = append(results, operand == rightHandOperand)
			break

		case "!=":
			results = append(results, operand != rightHandOperand)
			break

		case "LIKE":
			results = append(results, strings.Contains(operand, rightHandOperand))
			break

		case ">":
			convertedLeftHand, err := strconv.Atoi(operand)

			if err != nil {
				return false, err
			}

			convertedRightHand, err := strconv.Atoi(rightHandOperand)

			if err != nil {
				return false, err
			}

			results = append(results, convertedLeftHand > convertedRightHand)
			break

		case "<":
			convertedLeftHand, err := strconv.Atoi(operand)

			if err != nil {
				return false, err
			}

			convertedRightHand, err := strconv.Atoi(rightHandOperand)

			if err != nil {
				return false, err
			}

			results = append(results, convertedLeftHand < convertedRightHand)
			break

		case ">=":
			convertedLeftHand, err := strconv.Atoi(operand)

			if err != nil {
				return false, err
			}

			convertedRightHand, err := strconv.Atoi(rightHandOperand)

			if err != nil {
				return false, err
			}

			results = append(results, convertedLeftHand >= convertedRightHand)
			break

		case "<=":
			convertedLeftHand, err := strconv.Atoi(operand)

			if err != nil {
				return false, err
			}

			convertedRightHand, err := strconv.Atoi(rightHandOperand)

			if err != nil {
				return false, err
			}

			results = append(results, convertedLeftHand <= convertedRightHand)
			break

		default:
			return false, ErrorInvalidOperator
		}
	}

	for _, result := range results {
		if result {
			return true, nil
		}
	}

	return false, nil
}

func getNodeConvertedValue(value interface{}) string {
	stringValue, ok := value.(string)

	if !ok {
		boolValue, ok := value.(bool)

		if !ok {
			// Every numeric value in the template looks like
			// to be a FLOAT64
			floatValue, ok := value.(float64)

			if !ok {
				return ""
			}

			return strconv.Itoa(int(floatValue))
		}

		return strconv.FormatBool(boolValue)
	}

	return stringValue
}

func accessInnerNode(property string, node interface{}) (values []string) {
	properties := strings.Split(property, ".")
	currentProperty := properties[0]

	if arrayNode, ok := node.([]interface{}); ok {
		for _, subnode := range arrayNode {
			value := accessInnerNode(property, subnode)
			values = append(values, value...)
		}
	} else if mapNode, ok := node.(map[string]interface{}); ok {
		if len(properties) > 1 {
			value := accessInnerNode(strings.Join(properties[1:], "."), mapNode[currentProperty])
			values = append(values, value...)
			return
		}

		// There are some tricks about the CloudFormation template
		// That it holds Ref fields...
		if refNode, ok := mapNode["Ref"]; ok {
			refStringPlaceholder, ok := refNode.(string)

			if !ok {
				return
			}

			values = append(values, refStringPlaceholder)
			return
		}

		// Here we finally access the value of the current node
		// It's really weird for now, but we have to take care
		// about types and everything related to the conversion

		// Could be a array

		if arrayValues, ok := mapNode[currentProperty].([]interface{}); ok {
			for _, value := range arrayValues {
				stringValue := getNodeConvertedValue(value)

				if stringValue != "" {
					values = append(values, stringValue)
				}
			}

			return
		}

		stringValue := getNodeConvertedValue(mapNode[currentProperty])

		if stringValue != "" {
			values = append(values, stringValue)
		}
	}

	return
}

func formatPropertyAccess(property string) string {
	return fmt.Sprintf("Properties.%s", property)
}

func validateContext(context string) bool {
	for _, validContext := range validContexts {
		if validContext == context {
			return true
		}
	}

	return false
}

// CheckRule evals the desired rule against the already filtered and built node
func CheckRule(query lexer.Query, rootNode map[string]interface{}) (bool, error) {
	var leftHandSide []string
	var rightHandSide string
	var desiredNodeType string

	if query.Context == "Resources" {
		formattedResource := strings.ReplaceAll(query.Resource, ".", "::")
		desiredNodeType = fmt.Sprintf("AWS::%s", formattedResource)
		nodeType, ok := rootNode["Type"].(string)

		if !ok {
			return false, ErrorInvalidResource
		}

		if nodeType != desiredNodeType {
			return false, nil
		}
	}

	leftHandSide = accessInnerNode(formatPropertyAccess(query.Condition.LeftSide), rootNode)

	rightHandSide = string(query.Condition.RightSide)

	return evalCondition(leftHandSide, rightHandSide, query.Condition.Operator)
}

// CFQLFinding holds data about a specific finding
// inside the template being analyzed
type CFQLFinding struct {
	Message      string
	AffectedNode string
}

// QueryResult holds the information found for the given query against a CFNTemplate
type QueryResult struct {
	Errors           []string      `json:"errors,omitempty"`
	Findings         []CFQLFinding `json:"findings"`
	NumberOfFindings int           `json:"numberOfFindings"`
}

// AddError add a error message to the report
func (result *QueryResult) AddError(err error) {
	result.Errors = append(result.Errors, err.Error())
}

// AddFinding add a finding message to the report
func (result *QueryResult) AddFinding(message CFQLFinding) {
	result.Findings = append(result.Findings, message)
}

// RunQuery executes a single query inside the given Template
func RunQuery(
	query lexer.Query,
	template map[string]interface{}) (result QueryResult, haveFound bool) {
	isValidContext := validateContext(query.Context)

	if !isValidContext {
		result.AddError(ErrorInvalidContext)
		return
	}

	rawNodes := template[query.Context]

	if rawNodes == nil {
		result.AddError(ErrorEmptyContext)
		return
	}

	nodes, ok := rawNodes.(map[string]interface{})

	if !ok {
		result.AddError(ErrorEmptyContext)
		return
	}

	// Iterate through the dictionary, ignoring the keys*
	// * They are defined by the user, so basically random values :D
	for nodeName, rawNode := range nodes {
		node, ok := rawNode.(map[string]interface{})

		if !ok {
			result.AddError(ErrorInvalidResource)
		}

		haveFound, err := CheckRule(query, node)

		if err != nil {
			result.AddError(err)
		}

		if haveFound {
			result.AddFinding(CFQLFinding{
				Message:      query.Message,
				AffectedNode: string(nodeName),
			})
		}
	}

	result.NumberOfFindings = len(result.Findings)

	if len(result.Findings) > 0 {
		haveFound = true
		return
	}

	haveFound = false

	return
}

// RunQueries run all the given Queries against the template
func RunQueries(
	template map[string]interface{},
	queries []lexer.Query,
) (results []QueryResult) {
	for _, query := range queries {
		result, haveFound := RunQuery(query, template)

		if haveFound {
			results = append(results, result)
		}
	}

	return
}
