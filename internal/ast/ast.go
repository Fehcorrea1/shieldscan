package ast

type Node interface {
	GetType() string
	GetText() string
	GetLine() int
	GetColumn() int
	GetChildren() []Node
}

type BasicNode struct {
	Type     string
	Text     string
	Line     int
	Column   int
	Children []Node
}

func (n *BasicNode) GetType() string { return n.Type }
func (n *BasicNode) GetText() string { return n.Text }
func (n *BasicNode) GetLine() int { return n.Line }
func (n *BasicNode) GetColumn() int { return n.Column }
func (n *BasicNode) GetChildren() []Node { return n.Children }

// Walk performs a Depth-First Search traversal of the AST.
func Walk(node Node, visit func(Node)) {
	if node == nil {
		return
	}
	visit(node)
	for _, child := range node.GetChildren() {
		Walk(child, visit)
	}
}
