package user

import "testing"

func Test_printLog2Hist(t *testing.T) {
	vals := [6]int{20, 56, 78, 1, 255, 50}
	printLog2Hist(vals[0:], "xxx")
}

func Test_printLogHist(t *testing.T) {
	type_ := [6]string{"1", "2", "3", "4444", "5", "666666"}
	vals := [6]int{20, 56, 78, 96, 255, 50}
	printLogHist(type_[0:], vals[0:], "xxx")
}
