package utils

import (
	"encoding/json"
	"os"
)

type JsonStruct struct {
}

func NewJsonStruct() *JsonStruct {
	return &JsonStruct{}
}

func (js *JsonStruct) Load(fileName string, v interface{}) {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return
	}
	err = json.Unmarshal(data, v)
	if err != nil {
		return
	}
}
