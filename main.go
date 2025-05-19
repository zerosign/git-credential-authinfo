package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	gpgProgram    = "gpg"
	authInfoScope = "git"
)

var (
	files []string = []string{
		".authinfo.gpg",
		".authinfo",
		".netrc.gpg",
		".netrc",
	}
	logFile  *os.File
	isTraced bool = false
	homeDir  string
)

type Remote struct {
	Protocol string
	Host     string
	Username string
}

type Credential struct {
	Host        string
	Username    string
	Application string
	Password    string
}

func NextLineValue(scanner *bufio.Scanner, key string) (string, error) {
	if !scanner.Scan() {
		return "", fmt.Errorf("empty line")
	}

	value := scanner.Text()

	parts := strings.Split(value, "=")

	if len(parts) != 2 {
		return "", fmt.Errorf("value for '%s' not exists", key)
	}

	return parts[1], nil
}

func readRemoteLine(scanner *bufio.Scanner) (Remote, error) {

	if _, err := NextLineValue(scanner, "authtype"); err != nil {
		return Remote{}, err
	}

	if _, err := NextLineValue(scanner, "state"); err != nil {
		return Remote{}, err
	}

	protocol, err := NextLineValue(scanner, "protocol")

	if err != nil {
		return Remote{}, err
	}

	host, err := NextLineValue(scanner, "host")

	if err != nil {
		return Remote{}, err
	}

	username, err := NextLineValue(scanner, "username")

	if err != nil {
		return Remote{}, err
	}

	return Remote{
		Protocol: protocol,
		Host:     host,
		Username: username,
	}, nil
}

func readCredentialLine(line string) (Credential, error) {
	parts := strings.Split(line, " ")

	if len(parts) != 6 {
		return Credential{}, fmt.Errorf("line length mismatch, should be 6 words")
	}

	userApps := strings.Split(parts[3], "^")

	if len(userApps) != 2 {
		return Credential{}, fmt.Errorf("username & application doesn't exists")
	}

	return Credential{
		Host:        parts[1],
		Username:    userApps[0],
		Application: userApps[1],
		Password:    parts[5],
	}, nil
}

func Tracef(f string, v ...any) {
	if isTraced {
		log.Printf(f, v...)
	}
}

func Traceln(v ...any) {
	if isTraced {
		log.Println(v...)
	}
}

func init() {

	var err error

	flag, err := strconv.ParseBool(os.Getenv("LOGGING"))

	if err == nil {
		isTraced = flag
	}

	homeDir, err = os.UserHomeDir()

	if err != nil {
		log.Fatal(err)
	}

	logFile, err = os.OpenFile(filepath.Join(homeDir, "authinfo.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)

	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}

	log.SetOutput(logFile)
}

func main() {

	defer func() {
		if logFile != nil {
			logFile.Close()
		}
	}()

	stdinScanner := bufio.NewScanner(bufio.NewReader(os.Stdin))

	remote, err := readRemoteLine(stdinScanner)

	if err != nil {
		log.Fatal(err)
	}

	localHomeFs := os.DirFS(homeDir)

	for _, file := range files {

		if _, err := fs.Stat(localHomeFs, file); err == nil {

			authInfoPath := filepath.Join(homeDir, file)

			var raw []byte = nil

			if filepath.Ext(authInfoPath) == ".gpg" {

				Traceln("path: ", authInfoPath, filepath.Ext(authInfoPath))

				cmd := exec.Command(gpgProgram, "--decrypt", authInfoPath)
				// run with parent process environments
				cmd.Env = os.Environ()

				raw, err = cmd.Output()

				if err != nil {
					Tracef("\nerror on executing: %s, err: %s, msg: %s\n", cmd.String(), err, raw)
					log.Fatal("error on executing ", cmd.String(), " ", err)
				}
			} else {
				raw, err = fs.ReadFile(localHomeFs, file)

				if err != nil {
					log.Fatal(err)
				}
			}

			scanner := bufio.NewScanner(bytes.NewReader(raw))

			// machine [host] login [username]^[application] password [password]\n
			for scanner.Scan() {
				credential, err := readCredentialLine(scanner.Text())

				if err != nil {
					Tracef("\nerror on reading credential line: %s, err: %s\n", credential, err)
					log.Fatal(err)
				}

				Traceln(
					credential.Host, remote.Host, credential.Username, remote.Username,
					credential.Password,
					"check host equal: ",
					credential.Host == remote.Host,
					"check username equal: ",
					credential.Username == remote.Username,
				)

				if credential.Host == remote.Host &&
					credential.Username == remote.Username &&
					credential.Application == authInfoScope {

					// username=you\npassword=easy\n\n
					Tracef("username=%s\npassword=%s\n\n", credential.Username, credential.Password)
					fmt.Printf("username=%s\npassword=%s\n\n", credential.Username, credential.Password)

					return
				}
			}
		}
	}

}
