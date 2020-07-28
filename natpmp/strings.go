// Code generated by "stringer -type=Error -output=strings.go"; DO NOT EDIT.

package natpmp

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[success-0]
	_ = x[UnsupportedVersion-1]
	_ = x[NotAuthorized-2]
	_ = x[NetworkFailure-3]
	_ = x[OutOfResources-4]
	_ = x[UnsupportedOpcode-5]
}

const _Error_name = "successUnsupportedVersionNotAuthorizedNetworkFailureOutOfResourcesUnsupportedOpcode"

var _Error_index = [...]uint8{0, 7, 25, 38, 52, 66, 83}

func (i Error) String() string {
	if i < 0 || i >= Error(len(_Error_index)-1) {
		return "Error(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _Error_name[_Error_index[i]:_Error_index[i+1]]
}