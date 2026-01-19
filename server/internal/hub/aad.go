package hub

import (
	"bytes"
	"encoding/binary"
)

func BuildAAD(sender, recipient string, seq uint64) []byte {
	buf := bytes.Buffer{}
	buf.WriteString(sender)
	buf.WriteString(recipient)
	err := binary.Write(&buf, binary.BigEndian, seq)
	if err != nil {
		return nil
	}
	return buf.Bytes()
}
