package util

type ConnectionInfo struct {
	Dbhost, Dbport, Dbuser string
}

func ParseConnectionString(conn string) (*ConnectionInfo, error) {
	// TODO
	return nil, nil
}
