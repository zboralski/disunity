package render

// Theme holds colors for graph rendering.
type Theme struct {
	Background string
	NodeFill   string
	NodeBorder string
	TextColor  string

	EdgeDirect string // BL direct calls
	EdgeTHR    string // highlighted calls
	EdgePP     string // indirect calls

	ClusterBorder string
	ClusterLabel  string
}

// NASA is the NASA/Bauhaus theme.
var NASA = Theme{
	Background: "#F5F5F5",
	NodeFill:   "white",
	NodeBorder: "#1A1A1A",
	TextColor:  "#1A1A1A",

	EdgeDirect: "#424242",
	EdgeTHR:    "#0B3D91",
	EdgePP:     "#00695C",

	ClusterBorder: "#BDBDBD",
	ClusterLabel:  "#757575",
}
