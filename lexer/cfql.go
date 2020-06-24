package lexer

import (
	"errors"
	"io/ioutil"
	"log"
	"strings"
)

const cfQLRules string = "lexer/data/core.cfql"

const (
	// CommentaryTokenType is the signal to ignore the line
	CommentaryTokenType string = "//"

	// NullTokenType defines an error parsing the query
	NullTokenType string = "NULL"

	// OperatorTokenType defines a Operator in the query
	OperatorTokenType string = "OP"

	// PrimitiveTokenType defines a value that should be used in a
	// Operation
	PrimitiveTokenType string = "P"

	// OnTokenType defines which context and
	// resource should be used for the query
	OnTokenType string = "ON"
	// IfTokenType defines which property
	// and which desired value should be checked
	IfTokenType string = "IF"
	// ThenTokenType holds data about which message displays
	// if the condition returns True
	ThenTokenType string = "THEN"
	// GoTokenType defines the end of a query
	GoTokenType string = "GO"

	// ExistsOperator represents a special match case, to se if
	// the property exists
	ExistsOperator string = "EXISTS"
	// NotExistsOperator represents nullity match
	NotExistsOperator string = "NOT"
)

var (
	// ErrorMalformedQuery happens when there is any problem with
	// the token sequence for the any query
	ErrorMalformedQuery error = errors.New("malformed query")

	// ErrorInvalidQuery happens when there is
	// no ON operator in the beginning of a query
	ErrorInvalidQuery error = errors.New("invalid query operator precedence")

	// ErrorInvalidSyntaxONOperator happens when there is something wrong
	// with the value given for the ON operator
	ErrorInvalidSyntaxONOperator error = errors.New("invalid value for ON operator")

	// ErrorInvalidSyntaxIFOperator happens when there is something wrong
	// with the value given for a IF operator
	ErrorInvalidSyntaxIFOperator error = errors.New("invalid value for IF operator")

	// ErrorInvalidLeftSideIFOperator happens when the lexer cannot
	// parse the left hand side of a IF expression
	ErrorInvalidLeftSideIFOperator error = errors.New("invalid value for left hand side of IF operator")

	// ErrorInvalidOperatorIFOperator happens when the lexer cannot
	// parse the operator of a IF expression
	ErrorInvalidOperatorIFOperator error = errors.New("invalid value for an operator of IF operator")

	// ErrorInvalidRightSideIFOperator happens when the lexer cannot
	// parse the right hand side of a IF expression
	ErrorInvalidRightSideIFOperator error = errors.New("invalid value for right hand side of IF operator")

	// ErrorInvalidSyntaxTHENOperator happens when there is something wrong
	// with the parameter passed to the THEN operator
	ErrorInvalidSyntaxTHENOperator error = errors.New("invalid value for THEN operator")
)

func isOperator(content string) (bool, string) {
	formattedContent := strings.ToUpper(content)

	switch formattedContent {
	case OnTokenType:
		return true, formattedContent
		break
	case IfTokenType:
		return true, formattedContent
		break
	case ThenTokenType:
		return true, formattedContent
		break
	case GoTokenType:
		return true, formattedContent
		break
	}

	return false, ""
}

func isCommentary(content string) bool {
	return content == CommentaryTokenType
}

func isCommentaryToken(token Token) bool {
	return token.Type == CommentaryTokenType
}

func isPrimitiveToken(token Token) bool {
	return token.Type == PrimitiveTokenType
}

// Condition holds data about IF statements
type Condition struct {
	LeftSide  string
	RightSide string
	Operator  string
}

// Query is a CFQL query
type Query struct {
	Message   string    `json:"then"`
	Context   string    `json:"context"`
	Resource  string    `json:"resource"`
	Condition Condition `json:"condition"`
}

// Token defines a token to be used by the compiler
type Token struct {
	Type  string
	Value string
}

// NewNullToken returns a new token of type Null
func NewNullToken() Token {
	return Token{
		Type:  NullTokenType,
		Value: "",
	}
}

// NewCommentaryToken returns a new token of type Commentary
func NewCommentaryToken() Token {
	return Token{
		Type:  CommentaryTokenType,
		Value: "",
	}
}

// TokenTree holds data about all the tokens inside the query file
type TokenTree struct {
	pointer      int
	isFirstToken bool

	LastToken Token
	Tokens    []Token
}

// GetNextToken returns the next token and increments the pointer
func (tree *TokenTree) GetNextToken() (token Token, haveMore bool) {
	if tree.pointer >= len(tree.Tokens) {
		token = tree.LastToken
		haveMore = false

		return
	}

	token = tree.Tokens[tree.pointer]

	lastTokenIndex := tree.pointer - 1

	if lastTokenIndex >= 0 {
		tree.LastToken = tree.Tokens[lastTokenIndex]
	}

	tree.pointer++

	haveMore = true

	return
}

// ResetTreeWalk resets the internal counter
// so it will start to return all the previous tokens
// again
func (tree *TokenTree) ResetTreeWalk() {
	tree.pointer = 0
	tree.isFirstToken = true

	// Since its the first token to be returned, it should be null
	tree.LastToken = NewNullToken()
}

// AddToken adds a new Token to the internal tree
func (tree *TokenTree) AddToken(token Token) {
	tree.Tokens = append(tree.Tokens, token)
}

// AddNullToken adds a new Token of type Null to the internal tree
func (tree *TokenTree) AddNullToken() {
	tree.AddToken(NewNullToken())
}

// AddCommentaryToken adds a Commentary type token to the tree
func (tree *TokenTree) AddCommentaryToken() {
	tree.AddToken(NewCommentaryToken())
}

// Tokenize parses the hole file and creates the TokenTree for it
func Tokenize(content string) (tree TokenTree) {
	// Explicity sets the internal pointer to the beginning of a slice
	tree.ResetTreeWalk()

	lines := strings.Split(content, "\n")

	for _, rawLine := range lines {
		if rawLine == "" {
			continue
		}

		clearedLine := strings.TrimSpace(rawLine)
		line := strings.Split(clearedLine, " ")

		if isCommentary(line[0]) {
			continue
		}

		isValidOperator, operatorValue := isOperator(line[0])

		if isValidOperator {
			token := Token{
				Type:  OperatorTokenType,
				Value: operatorValue,
			}

			tree.AddToken(token)

			// Formats the value to become exactly what it was
			tokenValue := strings.Join((line[1:]), " ")

			if tokenValue != "" {
				valueToken := Token{
					Type:  PrimitiveTokenType,
					Value: tokenValue,
				}

				tree.AddToken(valueToken)
			}

			continue
		}
	}

	return
}

func parsesONValueToken(onValueToken Token) (context, resource string, err error) {
	if onValueToken.Type != PrimitiveTokenType {
		err = ErrorMalformedQuery
		return
	}

	queryFullContext := strings.Split(onValueToken.Value, ".")
	queryContext := queryFullContext[0]

	if queryContext == "" {
		err = ErrorInvalidSyntaxONOperator
		return
	}

	context = queryContext
	// Restore the rest for the Resource field
	resource = strings.Join(queryFullContext[1:], ".")

	return
}

func parsesIFValueToken(ifValueToken Token) (condition Condition, err error) {
	if ifValueToken.Type != PrimitiveTokenType {
		err = ErrorInvalidSyntaxIFOperator
		return
	}

	rawValue := strings.Split(ifValueToken.Value, " ")

	if len(rawValue) < 2 {
		err = ErrorInvalidSyntaxIFOperator
		return
	}

	leftHand := rawValue[0]
	operator := rawValue[1]

	if leftHand == "" {
		err = ErrorInvalidLeftSideIFOperator
		return
	}

	if operator == "" {
		err = ErrorInvalidOperatorIFOperator
		return
	}

	condition.LeftSide = leftHand
	condition.Operator = operator

	if IsExistsOperation(operator) {
		condition.RightSide = ""
		return
	}

	// If is not EXISTS, should have a right side
	rightHand := rawValue[2]

	if rightHand == "" {
		err = ErrorInvalidRightSideIFOperator
		return
	}

	if strings.Contains(rightHand, "\"") {
		condition.RightSide = strings.ReplaceAll(rightHand, "\"", "")
	} else {
		condition.RightSide = rightHand
	}

	return
}

func parseTHENValueToken(thenValueToken Token) (message string, err error) {
	if thenValueToken.Type != PrimitiveTokenType {
		err = ErrorInvalidSyntaxTHENOperator
		return
	}

	if strings.Contains(thenValueToken.Value, "\"") {
		message = strings.ReplaceAll(thenValueToken.Value, "\"", "")
		return
	}

	message = thenValueToken.Value
	return
}

// GenerateQuery gets a TokenTree and returns since it were able to form a new Query
// WARNING: It will move the internal Tree pointer
func GenerateQuery(tokenTree *TokenTree, rootToken Token) (newQuery Query, err error) {
	if isPrimitiveToken(rootToken) {
		err = ErrorMalformedQuery
		return
	}

	// Assumes that the given token will be an OP token, since this function will move the
	// pointer if it needs
	if rootToken.Type != OperatorTokenType || rootToken.Value != OnTokenType {
		log.Printf("Type: %s", rootToken.Type)
		log.Printf("Value: %s", rootToken.Value)

		err = ErrorInvalidQuery
		return
	}

	// ######################## ON OPERATOR ######################
	// Parses the ON token
	onValueToken, haveMore := tokenTree.GetNextToken()

	if !haveMore {
		err = ErrorMalformedQuery
		return
	}

	context, resource, err := parsesONValueToken(onValueToken)

	if err != nil {
		return
	}

	// Commits the results
	newQuery.Context = context
	newQuery.Resource = resource

	// ######################## IF OPERATOR ######################
	// Move on to the IF token
	ifToken, haveMore := tokenTree.GetNextToken()

	if !haveMore {
		err = ErrorMalformedQuery
		return
	}

	if ifToken.Type != OperatorTokenType || ifToken.Value == GoTokenType {
		err = ErrorMalformedQuery
		return
	}

	ifValueToken, haveMore := tokenTree.GetNextToken()

	if !haveMore {
		err = ErrorMalformedQuery
		return
	}

	condition, err := parsesIFValueToken(ifValueToken)

	if err != nil {
		return
	}

	newQuery.Condition = condition

	// ###################### THEN OPERATOR ####################
	// Move on to the THEN token
	thenToken, haveMore := tokenTree.GetNextToken()

	if !haveMore {
		err = ErrorMalformedQuery
		return
	}

	if thenToken.Type != OperatorTokenType || thenToken.Value == GoTokenType {
		err = ErrorInvalidQuery
		return
	}

	thenValueToken, haveMore := tokenTree.GetNextToken()

	if !haveMore {
		err = ErrorMalformedQuery
		return
	}

	message, err := parseTHENValueToken(thenValueToken)

	if err != nil {
		return
	}

	newQuery.Message = message

	// Move on to the GO operator
	// Only in this case we don't care at all about the
	// status, because this query should be over anyway
	goToken, _ := tokenTree.GetNextToken()

	if goToken.Type != OperatorTokenType || goToken.Value != GoTokenType {
		err = ErrorMalformedQuery
		return
	}

	return
}

func execTokenTree(tokenTree TokenTree) (queries []Query, err error) {
	for {
		token, haveMore := tokenTree.GetNextToken()

		if !haveMore {
			break
		}

		query, queryError := GenerateQuery(&tokenTree, token)

		if queryError != nil {
			err = queryError
			return
		}

		queries = append(queries, query)
	}

	return
}

// IsExistsOperation checks to see if the IF operator is EXISTS or NOT EXISTS
// special operations
func IsExistsOperation(operator string) bool {
	return operator == ExistsOperator || operator == NotExistsOperator
}

// ParseQuery gets a query string and return the correspondent queries
func ParseQuery(query string) (queries []Query, err error) {
	tokenTree := Tokenize(query)

	queries, err = execTokenTree(tokenTree)

	return
}

// LoadIaCRules is a special lexer for the CFQL language
// that loads the rules to query a IaC project
func LoadIaCRules() (queries []Query, err error) {
	physicalRuleFile := resolveToRuleDataFolder(cfQLRules)

	fileContent, err := ioutil.ReadFile(physicalRuleFile)

	if err != nil {
		return
	}

	queries, err = ParseQuery(string(fileContent))

	return
}
