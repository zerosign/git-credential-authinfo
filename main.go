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
	"strings"
)

const (
	gpgProgram = "gpg"
)

var (
	files []string = []string{
		".authinfo.gpg",
		".authinfo",
		".netrc.gpg",
		".netrc",
	}
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

func main() {

	homeDir, err := os.UserHomeDir()

	if err != nil {
		log.Fatal(err)
	}

	logFile, err := os.OpenFile(filepath.Join(homeDir, "authinfo.log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)

	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}

	defer logFile.Close()

	log.SetOutput(logFile)

	stdinScanner := bufio.NewScanner(bufio.NewReader(os.Stdin))

	remote, err := readRemoteLine(stdinScanner)

	if err != nil {
		log.Fatal(err)
	}

	localHomeFs := os.DirFS(homeDir)

	for _, file := range files {

		if _, err := fs.Stat(localHomeFs, file); err == nil {

			authInfoPath := filepath.Join(homeDir, file)

			if filepath.Ext(authInfoPath) == ".gpg" {

				log.Println("path: ", authInfoPath, filepath.Ext(authInfoPath))

				cmd := exec.Command(gpgProgram, "--decrypt", authInfoPath)
				raw, err := cmd.Output()

				if err != nil {
					log.Fatal("error on executing ", cmd.String(), " ", err)
				}

				scanner := bufio.NewScanner(bytes.NewReader(raw))

				// machine [host] login [username]^[application] password [password]\n
				for scanner.Scan() {
					credential, err := readCredentialLine(scanner.Text())

					if err != nil {
						log.Fatal(err)
					}

					log.Println(credential.Host, remote.Host, credential.Username, remote.Username)

					if credential.Host == remote.Host && credential.Username == remote.Username {
						// username=you\npassword=easy\n\n
						log.Printf("username=%s\npassword=%s\n\n", credential.Username, credential.Password)
					}
				}
			}
		}
	}

}
