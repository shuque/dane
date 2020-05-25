package dane

import (
	"fmt"
)

//
// TLSArdata - TLSA rdata structure
//
type TLSArdata struct {
	usage    uint8
	selector uint8
	mtype    uint8
	data     string
	checked  bool
	ok       bool
	message  string
}

//
// String returns a string representation of the TLSA rdata.
//
func (tr *TLSArdata) String() string {
	return fmt.Sprintf("DANE TLSA %d %d %d [%s..]",
		tr.usage, tr.selector, tr.mtype, tr.data[0:8])
}

//
// TLSAinfo contains details of the TLSA RRset.
//
type TLSAinfo struct {
	qname string
	alias []string
	rdata []*TLSArdata
}

//
// Uncheck unchecks result fields of all the TLSA rdata structs.
//
func (t *TLSAinfo) Uncheck() {
	for _, tr := range t.rdata {
		tr.checked = false
		tr.ok = false
		tr.message = ""
	}
}

//
// Results prints TLSA RRset certificate matching results.
//
func (t *TLSAinfo) Results() {
	if t.rdata == nil {
		fmt.Printf("No TLSA records available.\n")
		return
	}
	for _, tr := range t.rdata {
		if !tr.checked {
			fmt.Printf("%s: not checked\n", tr)
		} else if tr.ok {
			fmt.Printf("%s: OK %s\n", tr, tr.message)
		} else {
			fmt.Printf("%s: FAIL %s\n", tr, tr.message)
		}
	}
}

//
// Print prints information about the TLSAinfo TLSA RRset.
func (t *TLSAinfo) Print() {
	fmt.Printf("DNS TLSA RRset:\n  qname: %s\n", t.qname)
	if t.alias != nil {
		fmt.Printf("  alias: %s\n", t.alias)
	}
	for _, trdata := range t.rdata {
		fmt.Printf("  %d %d %d %s\n", trdata.usage, trdata.selector,
			trdata.mtype, trdata.data)
	}
}
