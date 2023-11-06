package form

type Cases struct {
	Name            string `json:"name"`
	Sex             string `json:"sex"`
	Age             string `json:"age"`
	Check_Item      string `json:"check_item"`
	Describe        string `json:"describe"`
	Doctor          string `json:"doctor"`
	Medical         string `json:"medical"`
	Hospital        string `json:"hospital"`
	Diagnostic_Time string `json:"diagnostic_time"`
}

type CipherCases struct {
	File_Type string `json:"file_type"`
	CapsuleE  string `json:"capsuleE"`
	CapsuleV  string `json:"capsuleV"`
	CapsuleS  string `json:"capsuleS"`
	Cipher    []byte `json:"cipher"`
}

type ReEncryptCases struct {
	File_Type   string `json:"file_type"`
	CapsuleE    string `json:"capsuleE"`
	CapsuleV    string `json:"capsuleV"`
	CapsuleS    string `json:"capsuleS"`
	NewCapsuleE string `json:"newcapsuleE"`
	NewCapsuleV string `json:"newcapsuleV"`
	NewCapsuleS string `json:"newcapsuleS"`
	PubX        string `json:"pubX"`
	Cipher      []byte `json:"cipher"`
}
