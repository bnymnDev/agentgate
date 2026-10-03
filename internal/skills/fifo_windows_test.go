package skills

import "errors"

func mkfifo(string) error { return errors.New("no named pipes on Windows") }
