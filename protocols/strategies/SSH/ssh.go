package SSH

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mariocandela/beelzebub/v3/historystore"
	"github.com/mariocandela/beelzebub/v3/parser"
	"github.com/mariocandela/beelzebub/v3/plugins"
	"github.com/mariocandela/beelzebub/v3/tracer"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

var urlRegex = regexp.MustCompile(`https?://[^\s'"` + "`" + `|;&)>]+`)

const samplesDir = "/samples"

// handleSCPUpload implements the SCP sink protocol to capture files uploaded by attackers.
func handleSCPUpload(sess ssh.Session, sourceIp, user string, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration) {
	if err := os.MkdirAll(samplesDir, 0750); err != nil {
		log.Errorf("SCP: failed to create samples dir: %s", err)
		sess.Write([]byte{0x02})
		return
	}

	sess.Write([]byte{0x00}) // ready

	reader := bufio.NewReader(sess)
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		header = strings.TrimRight(header, "\n\r")
		if len(header) == 0 {
			break
		}

		switch header[0] {
		case 'E': // end of directory
			sess.Write([]byte{0x00})
			return
		case 'C': // file copy: C<mode> <size> <filename>
			parts := strings.SplitN(header[1:], " ", 3)
			if len(parts) != 3 {
				return
			}
			size, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || size < 0 || size > 100*1024*1024 { // cap at 100 MB
				return
			}
			filename := filepath.Base(parts[2])

			sess.Write([]byte{0x00}) // ready for data

			data := make([]byte, size)
			if _, err := io.ReadFull(reader, data); err != nil {
				break
			}
			reader.ReadByte() // trailing \x00 from client

			timestamp := time.Now().UTC().Format("20060102T150405Z")
			savePath := filepath.Join(samplesDir, fmt.Sprintf("%s_%s_%s", timestamp, sourceIp, filename))
			if err := os.WriteFile(savePath, data, 0600); err != nil {
				log.Errorf("SCP: failed to save sample %s: %s", savePath, err)
			} else {
				log.WithFields(log.Fields{
					"filename": filename,
					"size":     size,
					"sourceIp": sourceIp,
					"path":     savePath,
				}).Warn("SCP sample captured")
			}

			sess.Write([]byte{0x00}) // ack

			tr.TraceEvent(tracer.Event{
				Msg:         "SCP Upload — Sample Captured",
				Protocol:    tracer.SSH.String(),
				Status:      tracer.Stateless.String(),
				SourceIp:    sourceIp,
				User:        user,
				Command:     fmt.Sprintf("scp %s (%d bytes)", filename, size),
				Description: servConf.Description,
			})
		default:
			return
		}
	}
}

// parseSCPPath extracts the file path from an scp command string.
// e.g. "scp -f -p /etc/passwd" → "/etc/passwd"
func parseSCPPath(command string) string {
	parts := strings.Fields(command)
	for i := len(parts) - 1; i >= 0; i-- {
		if !strings.HasPrefix(parts[i], "-") && parts[i] != "scp" {
			return parts[i]
		}
	}
	return ""
}

// handleSCPDownload serves a Claude-generated deceptive file when an attacker
// pulls a file from the honeypot via SCP (scp -f <path>).
func handleSCPDownload(sess ssh.Session, path string, sourceIp, user string, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration) {
	if path == "" {
		sess.Write([]byte{0x02})
		return
	}

	filename := filepath.Base(path)

	llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
	if err != nil {
		log.Errorf("SCP download: invalid LLM provider: %s", err)
		sess.Write([]byte{0x02})
		return
	}

	fileServConf := servConf
	fileServConf.Plugin.Prompt = fmt.Sprintf(
		"%s\n\nGenerate realistic raw file contents for the path `%s` on this system. "+
			"Reply with ONLY the raw file contents — no markdown, no code fences, no explanations.",
		servConf.Plugin.Prompt, path,
	)

	hp := plugins.BuildHoneypot(nil, tracer.SSH, llmProvider, fileServConf)
	instance := plugins.InitLLMHoneypot(*hp)

	content, err := instance.ExecuteModel("cat " + path)
	if err != nil {
		log.Errorf("SCP download: LLM generation failed for %s: %s", path, err)
		sess.Write([]byte("\x01No such file or directory\n"))
		return
	}

	data := []byte(content)

	// Save a copy of what we served so defenders can review it
	if mkErr := os.MkdirAll(samplesDir, 0750); mkErr == nil {
		timestamp := time.Now().UTC().Format("20060102T150405Z")
		savePath := filepath.Join(samplesDir, fmt.Sprintf("%s_%s_served_%s", timestamp, sourceIp, filename))
		if writeErr := os.WriteFile(savePath, data, 0600); writeErr != nil {
			log.Errorf("SCP download: failed to save served sample: %s", writeErr)
		}
	}

	// SCP source protocol:
	// 1. Read client ready signal
	buf := make([]byte, 1)
	if _, err := io.ReadFull(sess, buf); err != nil || buf[0] != 0 {
		return
	}

	// 2. Send file header: C<mode> <size> <filename>\n
	header := fmt.Sprintf("C0644 %d %s\n", len(data), filename)
	if _, err := sess.Write([]byte(header)); err != nil {
		return
	}

	// 3. Read go-ahead
	if _, err := io.ReadFull(sess, buf); err != nil || buf[0] != 0 {
		return
	}

	// 4. Send file data
	sess.Write(data)

	// 5. End-of-data marker
	sess.Write([]byte{0x00})

	// 6. Read final ack (best-effort)
	io.ReadFull(sess, buf) //nolint:errcheck

	log.WithFields(log.Fields{
		"path":     path,
		"size":     len(data),
		"sourceIp": sourceIp,
	}).Warn("SCP download — deceptive file served")

	tr.TraceEvent(tracer.Event{
		Msg:         "SCP Download — Deceptive File Served",
		Protocol:    tracer.SSH.String(),
		Status:      tracer.Stateless.String(),
		SourceIp:    sourceIp,
		User:        user,
		Command:     fmt.Sprintf("scp -f %s (%d bytes served)", path, len(data)),
		Description: servConf.Description,
	})
}

// captureWgetCurl checks if a command contains wget/curl and fetches any URLs found in the background.
func captureWgetCurl(command, sourceIp, user string, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration) {
	lower := strings.ToLower(command)
	if !strings.Contains(lower, "wget") && !strings.Contains(lower, "curl") {
		return
	}
	urls := urlRegex.FindAllString(command, -1)
	for _, u := range urls {
		go fetchAndSaveSample(u, sourceIp, user, tr, servConf)
	}
}

func fetchAndSaveSample(rawURL, sourceIp, user string, tr tracer.Tracer, servConf parser.BeelzebubServiceConfiguration) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(rawURL)
	if err != nil {
		log.Warnf("wget/curl capture: failed to fetch %s: %s", rawURL, err)
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // cap 10 MB
	if err != nil {
		log.Warnf("wget/curl capture: failed to read %s: %s", rawURL, err)
		return
	}

	filename := filepath.Base(parsed.Path)
	if filename == "." || filename == "/" || filename == "" {
		filename = "index"
	}

	if err := os.MkdirAll(samplesDir, 0750); err != nil {
		log.Errorf("wget/curl capture: mkdir failed: %s", err)
		return
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	savePath := filepath.Join(samplesDir, fmt.Sprintf("%s_%s_%s", timestamp, sourceIp, filename))

	if err := os.WriteFile(savePath, data, 0600); err != nil {
		log.Errorf("wget/curl capture: save failed %s: %s", savePath, err)
		return
	}

	log.WithFields(log.Fields{
		"url":      rawURL,
		"size":     len(data),
		"sourceIp": sourceIp,
		"path":     savePath,
	}).Warn("wget/curl sample captured")

	tr.TraceEvent(tracer.Event{
		Msg:         "wget/curl — Sample Captured",
		Protocol:    tracer.SSH.String(),
		Status:      tracer.Stateless.String(),
		SourceIp:    sourceIp,
		User:        user,
		Command:     fmt.Sprintf("fetch %s (%d bytes)", rawURL, len(data)),
		Description: servConf.Description,
	})
}

type SSHStrategy struct {
	Sessions *historystore.HistoryStore
}

func (sshStrategy *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if sshStrategy.Sessions == nil {
		sshStrategy.Sessions = historystore.NewHistoryStore()
	}
	go sshStrategy.Sessions.HistoryCleaner()
	go func() {
		server := &ssh.Server{
			Addr:        servConf.Address,
			MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
			Version:     servConf.ServerVersion,
			Handler: func(sess ssh.Session) {
				uuidSession := uuid.New()

				host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
				sessionKey := "SSH" + host + sess.User()

				// Inline SSH command
				if sess.RawCommand() != "" {
					// Intercept SCP uploads before LLM handling
					if strings.Contains(sess.RawCommand(), "scp") && strings.Contains(sess.RawCommand(), "-t") {
						handleSCPUpload(sess, host, sess.User(), tr, servConf)
						return
					}
					// Intercept SCP downloads — serve Claude-generated deceptive files
					if strings.Contains(sess.RawCommand(), "scp") && strings.Contains(sess.RawCommand(), "-f") {
						handleSCPDownload(sess, parseSCPPath(sess.RawCommand()), host, sess.User(), tr, servConf)
						return
					}

					var histories []plugins.Message
					if sshStrategy.Sessions.HasKey(sessionKey) {
						histories = sshStrategy.Sessions.Query(sessionKey)
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(sess.RawCommand()) {
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("error: %s", err.Error())
									commandOutput = "command not found"
									llmProvider = plugins.OpenAI
								}
								llmHoneypot := plugins.BuildHoneypot(histories, tracer.SSH, llmProvider, servConf)
								llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
								if commandOutput, err = llmHoneypotInstance.ExecuteModel(sess.RawCommand()); err != nil {
									log.Errorf("error ExecuteModel: %s, %s", sess.RawCommand(), err.Error())
									commandOutput = "command not found"
								}
							}
							var newEntries []plugins.Message
							captureWgetCurl(sess.RawCommand(), host, sess.User(), tr, servConf)

							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: sess.RawCommand()})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Append the new entries to the store.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)

							sess.Write(append([]byte(commandOutput), '\n'))

							tr.TraceEvent(tracer.Event{
								Msg:           "SSH Raw Command",
								Protocol:      tracer.SSH.String(),
								RemoteAddr:    sess.RemoteAddr().String(),
								SourceIp:      host,
								SourcePort:    port,
								Status:        tracer.Start.String(),
								ID:            uuidSession.String(),
								Environ:       strings.Join(sess.Environ(), ","),
								User:          sess.User(),
								Description:   servConf.Description,
								Command:       sess.RawCommand(),
								CommandOutput: commandOutput,
								Handler:       command.Name,
							})
							return
						}
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:         "New SSH Terminal Session",
					Protocol:    tracer.SSH.String(),
					RemoteAddr:  sess.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					Status:      tracer.Start.String(),
					ID:          uuidSession.String(),
					Environ:     strings.Join(sess.Environ(), ","),
					User:        sess.User(),
					Description: servConf.Description,
				})

				terminal := term.NewTerminal(sess, buildPrompt(sess.User(), servConf.ServerName))
				var histories []plugins.Message
				if sshStrategy.Sessions.HasKey(sessionKey) {
					histories = sshStrategy.Sessions.Query(sessionKey)
				}

				for {
					commandInput, err := terminal.ReadLine()
					if err != nil {
						break
					}
					if commandInput == "exit" {
						break
					}
					for _, command := range servConf.Commands {
						if command.Regex.MatchString(commandInput) {
							commandOutput := command.Handler
							if command.Plugin == plugins.LLMPluginName {
								llmProvider, err := plugins.FromStringToLLMProvider(servConf.Plugin.LLMProvider)
								if err != nil {
									log.Errorf("error: %s, fallback OpenAI", err.Error())
									llmProvider = plugins.OpenAI
								}
								llmHoneypot := plugins.BuildHoneypot(histories, tracer.SSH, llmProvider, servConf)
								llmHoneypotInstance := plugins.InitLLMHoneypot(*llmHoneypot)
								if commandOutput, err = llmHoneypotInstance.ExecuteModel(commandInput); err != nil {
									log.Errorf("error ExecuteModel: %s, %s", commandInput, err.Error())
									commandOutput = "command not found"
								}
							}
							captureWgetCurl(commandInput, host, sess.User(), tr, servConf)

							var newEntries []plugins.Message
							newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
							newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
							// Stash the new entries to the store, and update the history for this running session.
							sshStrategy.Sessions.Append(sessionKey, newEntries...)
							histories = append(histories, newEntries...)

							terminal.Write(append([]byte(commandOutput), '\n'))

							tr.TraceEvent(tracer.Event{
								Msg:           "SSH Terminal Session Interaction",
								RemoteAddr:    sess.RemoteAddr().String(),
								SourceIp:      host,
								SourcePort:    port,
								Status:        tracer.Interaction.String(),
								Command:       commandInput,
								CommandOutput: commandOutput,
								ID:            uuidSession.String(),
								Protocol:      tracer.SSH.String(),
								Description:   servConf.Description,
								Handler:       command.Name,
							})
							break // Inner range over commands.
						}
					}
				}

				tr.TraceEvent(tracer.Event{
					Msg:      "End SSH Session",
					Status:   tracer.End.String(),
					ID:       uuidSession.String(),
					Protocol: tracer.SSH.String(),
				})
			},
			PasswordHandler: func(ctx ssh.Context, password string) bool {
				host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

				tr.TraceEvent(tracer.Event{
					Msg:         "New SSH Login Attempt",
					Protocol:    tracer.SSH.String(),
					Status:      tracer.Stateless.String(),
					User:        ctx.User(),
					Password:    password,
					Client:      ctx.ClientVersion(),
					RemoteAddr:  ctx.RemoteAddr().String(),
					SourceIp:    host,
					SourcePort:  port,
					ID:          uuid.New().String(),
					Description: servConf.Description,
				})
				matched, err := regexp.MatchString(servConf.PasswordRegex, password)
				if err != nil {
					log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
					return false
				}
				return matched
			},
		}
		err := server.ListenAndServe()
		if err != nil {
			log.Errorf("error during init SSH Protocol: %s", err.Error())
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("GetInstance service %s", servConf.Protocol)
	return nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}