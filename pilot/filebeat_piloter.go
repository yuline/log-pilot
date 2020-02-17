package pilot

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/elastic/go-ucfg"
	"github.com/elastic/go-ucfg/yaml"
)

// Global variables for FilebeatPiloter
const (
	FILEBEAT_EXEC_CMD  = "/usr/bin/filebeat"
	FILEBEAT_REGISTRY  = "/var/lib/filebeat/registry"
	FILEBEAT_BASE_CONF = "/etc/filebeat"
	FILEBEAT_CONF_DIR  = FILEBEAT_BASE_CONF + "/prospectors.d"
	FILEBEAT_CONF_FILE = FILEBEAT_BASE_CONF + "/filebeat.yml"

	DOCKER_SYSTEM_PATH  = "/var/lib/docker/"
	KUBELET_SYSTEM_PATH = "/var/lib/kubelet/"

	ENV_FILEBEAT_OUTPUT = "FILEBEAT_OUTPUT"
)

var filebeat *exec.Cmd
var _ Piloter = (*FilebeatPiloter)(nil)

// FilebeatPiloter for filebeat plugin
type FilebeatPiloter struct {
	name           string
	baseDir        string
	watchDone      chan bool
	watchDuration  time.Duration
	watchContainer map[string]string
	fbExit         chan struct{}
	noticeStop     chan bool
}

// NewFilebeatPiloter returns a FilebeatPiloter instance
func NewFilebeatPiloter(baseDir string) (Piloter, error) {
	return &FilebeatPiloter{
		name:           PILOT_FILEBEAT,
		baseDir:        baseDir,
		watchDone:      make(chan bool),
		watchContainer: make(map[string]string, 0),
		watchDuration:  150 * time.Second,
		fbExit:         make(chan struct{}),
		noticeStop:     make(chan bool, 1),
	}, nil
}

var configOpts = []ucfg.Option{
	ucfg.PathSep("."),
	ucfg.ResolveEnv,
	ucfg.VarExp,
}

// Config contains all log paths
type Config struct {
	Paths []string `config:"paths"`
}

// FileInode identify a unique log file
type FileInode struct {
	Inode  uint64 `json:"inode,"`
	Device uint64 `json:"device,"`
}

// RegistryState represents log offsets
type RegistryState struct {
	Source      string        `json:"source"`
	Offset      int64         `json:"offset"`
	Timestamp   time.Time     `json:"timestamp"`
	TTL         time.Duration `json:"ttl"`
	Type        string        `json:"type"`
	FileStateOS FileInode
}

func (p *FilebeatPiloter) watch() error {
	log.Infof("%s watcher start", p.Name())
	for {
		select {
		case <-p.watchDone:
			log.Infof("%s watcher stop", p.Name())
			return nil
		case <-time.After(p.watchDuration):
			//log.Debugf("%s watcher scan", p.Name())
			err := p.scan()
			if err != nil {
				log.Errorf("%s watcher scan error: %v", p.Name(), err)
			}
		}
	}
}

func (p *FilebeatPiloter) newWatch(cmd *exec.Cmd) error {
	log.Infof("%s watcher start", p.Name())
	for {
		select {
		case <-p.watchDone:
			log.Infof("%s watcher stop", p.Name())
			p.noticeStop <- true

			err := cmd.Process.Kill()
			if err != nil {
				pgroup := 0 - cmd.Process.Pid
				syscall.Kill(pgroup, syscall.SIGKILL)
			}
			time.Sleep(3 * time.Second) // wait a little
			p.fbExit <- struct{}{}
			return err
		case <-time.After(p.watchDuration):
			log.Debugf("%s watcher scan", p.Name())
			go func(){
				err := p.newScan()
				if err != nil {
					log.Errorf("%s watcher scan error: %v", p.Name(), err)
				}
			}()
		}
	}
}

func (p *FilebeatPiloter) scan() error {
	states, err := p.getRegsitryState()
	if err != nil {
		return nil
	}

	configPaths := p.loadConfigPaths()
	for container := range p.watchContainer {
		confPath := p.GetConfPath(container)
		if _, err := os.Stat(confPath); err != nil && os.IsNotExist(err) {
			log.Infof("log config %s.yml has been removed and ignore", container)
			delete(p.watchContainer, container)
		} else if p.canRemoveConf(container, states, configPaths) {
			// 在这里加入自定义的补充动作。
			// 这里config文件的清理动作做一个调整：
			//   不在循环中进行实际的文件删除动作，每次循环只记录要执行删除的container, 在循环结束后统一处理。
			log.Infof("try to remove log config %s.yml", container)
			if err := os.Remove(confPath); err != nil {
				log.Errorf("remove log config %s.yml fail: %v", container, err)
			} else {
				delete(p.watchContainer, container)
			}
		}
	}
	return nil
}

func (p *FilebeatPiloter) newScan() error {
	states, err := p.getRegsitryState()
	if err != nil {
		log.Error("Get registry error: ", err)
		return err
	}

	configPaths := p.loadConfigPaths()
	delConfs := make(map[string]string)
	delLogs := make(map[string]string)
	log.Debug("Will delete containers: ", p.watchContainer)
	for container := range p.watchContainer {
		confPath := p.GetConfPath(container)
		if _, err := os.Stat(confPath); err != nil && os.IsNotExist(err) {
			log.Infof("log config %s.yml has been removed and ignore", container)
			delete(p.watchContainer, container)
		} else if logm, b := p.newCanRemoveConf(container, states, configPaths); b{
			// 在这里加入自定义的补充动作。
			// 这里config文件的清理动作做一个调整：
			//   不在循环中进行实际的文件删除动作，每次循环只记录要执行删除的container, 在循环结束后统一处理。
			delConfs[confPath] = container
			for log, c := range logm {
				delLogs[log] = c
			}
		}
	}
	if len(delConfs) == 0 {
		log.Debugf("No filebeat config will modify, current scan end")
		return nil
	}

	// 对filebeat进行container释放清理操作
	p.Stop() //停止filebeat
	<- p.fbExit  //等待filebeat退出
	defer func(){
		time.Sleep(10 * time.Second)
		p.Start()
	}()
	 

	log.Debug("Will delete conf: ", delConfs)
	log.Debug("Will clean registry item: ", delLogs)
	b, _ := ioutil.ReadFile(FILEBEAT_REGISTRY)
	origStates := make([]RegistryState, 0)
	newStates := make([]RegistryState, 0)
	if err := json.Unmarshal(b, &origStates); err != nil {
		log.Error("json error: ", err)
		return err
	}

	failDelContainers := make(map[string]bool)
	// 删除detroyed container的配置文件
	for delConf, container := range delConfs{
		log.Debug("start remove conf: ", delConf)
		if err := os.Remove(delConf); err != nil {
			log.Errorf("remove log config %s.yml fail: %v", container, err)
			failDelContainers[container] = true
		}else{
			log.Infof("%s removed", delConf)
			delete(p.watchContainer, container)
		}
	}

	// 更新registry文件
	for _, state := range origStates {
		if !FileExist(state.Source){
			//当前的文件已经被删除了，可能是未清理的过期配置
			log.Debugf("logfile(%s) has been removed, the item could be deleted: %v", state.Source, state)
			continue
		}else if container, ok := delLogs[state.Source]; !ok {
			//当前state不是destroying container的log，需要继续保留
			newStates = append(newStates, state)
		}else if _, ok := failDelContainers[container]; ok {
			//当前state是destroying container的log，但是conf文件删除失败了，也需要继续保留
			newStates = append(newStates, state)
		}
	}
	nb, err := json.Marshal(newStates)
	if err != nil {
		return err
	}
	log.Debug("Update registry: ")
	log.Debug("Orig registry: ", origStates)
	log.Debug("New registry: ", newStates)
	return ioutil.WriteFile(FILEBEAT_REGISTRY, nb, 0600)
}

func (p *FilebeatPiloter) newCanRemoveConf(container string, registry map[string]RegistryState,
	configPaths map[string]string) (map[string]string, bool) {
	config, err := p.loadConfig(container)
	if err != nil {
		log.Error(err)
		return nil, false
	}
	
	delLogs := make(map[string]string)
	for _, path := range config.Paths {
		autoMount := p.isAutoMountPath(filepath.Dir(path))
		logFiles, _ := filepath.Glob(path)
		for _, logFile := range logFiles {
			info, err := os.Stat(logFile)
			if err != nil && os.IsNotExist(err) {
				continue
			}
			if _, ok := registry[logFile]; !ok {
				log.Warnf("%s->%s registry not exist", container, logFile)
				continue
			}
			if registry[logFile].Offset < info.Size() {
				if autoMount { // ephemeral(短暂的、瞬息的) logs
					log.Infof("%s->%s does not finish to read", container, logFile)
					return nil, false
				} else if _, ok := configPaths[path]; !ok { // host path bind
					// 目前还不是很明白什么情况下会出现这个状况。
					log.Infof("%s->%s does not finish to read and not exist in other config",
						container, logFile)
					return nil, false
				}
			}
			delLogs[logFile] = container
		}
	}
	return delLogs, true
}

func (p *FilebeatPiloter) canRemoveConf(container string, registry map[string]RegistryState,
	configPaths map[string]string) bool {
	config, err := p.loadConfig(container)
	if err != nil {
		return false
	}

	for _, path := range config.Paths {
		autoMount := p.isAutoMountPath(filepath.Dir(path))
		logFiles, _ := filepath.Glob(path)
		for _, logFile := range logFiles {
			info, err := os.Stat(logFile)
			if err != nil && os.IsNotExist(err) {
				continue
			}
			if _, ok := registry[logFile]; !ok {
				log.Warnf("%s->%s registry not exist", container, logFile)
				continue
			}
			if registry[logFile].Offset < info.Size() {
				if autoMount { // ephemeral(短暂的、瞬息的) logs
					log.Infof("%s->%s does not finish to read", container, logFile)
					return false
				} else if _, ok := configPaths[path]; !ok { // host path bind
					// 目前还不是很明白什么情况下会出现这个状况。
					log.Infof("%s->%s does not finish to read and not exist in other config",
						container, logFile)
					return false
				}
			}
		}
	}
	return true
}

func (p *FilebeatPiloter) loadConfig(container string) (*Config, error) {
	confPath := p.GetConfPath(container)
	c, err := yaml.NewConfigWithFile(confPath, configOpts...)
	if err != nil {
		log.Errorf("read %s.yml log config error: %v", container, err)
		return nil, err
	}

	var config Config

	var configs []Config
	var paths []string
	if err := c.Unpack(&configs); err != nil {
		log.Errorf("parse %s.yml log config error: %v", container, err)
		return nil, err
	}

	for _, c := range configs {
		paths = append(paths, c.Paths...)
	}
	config.Paths = paths
	return &config, nil
}

func (p *FilebeatPiloter) loadConfigPaths() map[string]string {
	paths := make(map[string]string, 0)
	confs, _ := ioutil.ReadDir(p.GetConfHome())
	for _, conf := range confs {
		container := strings.TrimRight(conf.Name(), ".yml")
		if _, ok := p.watchContainer[container]; ok {
			continue // ignore removed container
		}

		config, err := p.loadConfig(container)
		if err != nil || config == nil {
			continue
		}

		for _, path := range config.Paths {
			if _, ok := paths[path]; !ok {
				paths[path] = container
			}
		}
	}
	return paths
}

func (p *FilebeatPiloter) isAutoMountPath(path string) bool {
	dockerVolumePattern := fmt.Sprintf("^%s.*$", filepath.Join(p.baseDir, DOCKER_SYSTEM_PATH))
	if ok, _ := regexp.MatchString(dockerVolumePattern, path); ok {
		return true
	}

	kubeletVolumePattern := fmt.Sprintf("^%s.*$", filepath.Join(p.baseDir, KUBELET_SYSTEM_PATH))
	ok, _ := regexp.MatchString(kubeletVolumePattern, path)
	return ok
}

func (p *FilebeatPiloter) getRegsitryState() (map[string]RegistryState, error) {
	f, err := os.Open(FILEBEAT_REGISTRY)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	decoder := json.NewDecoder(f)
	states := make([]RegistryState, 0)
	err = decoder.Decode(&states)
	if err != nil {
		return nil, err
	}

	statesMap := make(map[string]RegistryState, 0)
	for _, state := range states {
		if _, ok := statesMap[state.Source]; !ok {
			statesMap[state.Source] = state
		}
	}
	return statesMap, nil
}

func (p *FilebeatPiloter) feed(containerID string) error {
	if _, ok := p.watchContainer[containerID]; !ok {
		p.watchContainer[containerID] = containerID
		log.Infof("begin to watch log config: %s.yml", containerID)
	}
	return nil
}

// Start starting and watching filebeat process
func (p *FilebeatPiloter) Start() error {
	log.Debug("Start the filebeat piloter")

	if filebeat != nil {
		pid := filebeat.Process.Pid
		process, err := os.FindProcess(pid)
		if err == nil{
			err = process.Signal(syscall.Signal(0))
			if err == nil{
				log.Infof("filebeat started, pid: %v", pid)
				return fmt.Errorf(ERR_ALREADY_STARTED)
			}
		}
	}

	log.Info("starting filebeat")
	filebeat = exec.Command(FILEBEAT_EXEC_CMD, "-c", FILEBEAT_CONF_FILE)
	filebeat.Stderr = os.Stderr
	filebeat.Stdout = os.Stdout
	err := filebeat.Start()
	if err != nil {
		log.Errorf("filebeat start fail: %v", err)
	}

	go func() {
		log.Infof("filebeat started: %v", filebeat.Process.Pid)
		select {
		case err := <- Func2Chan(filebeat.Wait):
			if err != nil {
				log.Errorf("filebeat exited: %v", err)
				if exitError, ok := err.(*exec.ExitError); ok {
					processState := exitError.ProcessState
					log.Errorf("filebeat exited pid: %v", processState.Pid())
				}
			}
	
			// try to restart filebeat
			log.Warningf("filebeat exited and try to restart")
			filebeat = nil
			p.Start()
		case <- p.noticeStop:
			return
		}
		// err := filebeat.Wait()
		// if err != nil {
		// 	log.Errorf("filebeat exited: %v", err)
		// 	if exitError, ok := err.(*exec.ExitError); ok {
		// 		processState := exitError.ProcessState
		// 		log.Errorf("filebeat exited pid: %v", processState.Pid())
		// 	}
		// }

		// // try to restart filebeat
		// log.Warningf("filebeat exited and try to restart")
		// filebeat = nil
		// p.Start()
	}()

	// go p.watch(filebeat)
	go p.newWatch(filebeat)
	return err
}

// Stop log collection
func (p *FilebeatPiloter) Stop() error {
	log.Debug("Stop the filebeat piloter")
	p.watchDone <- true
	return nil
}

// Reload reload configuration file
func (p *FilebeatPiloter) Reload() error {
	log.Debug("do not need to reload filebeat")
	return nil
}

// GetConfPath returns log configuration path
func (p *FilebeatPiloter) GetConfPath(container string) string {
	return fmt.Sprintf("%s/%s.yml", FILEBEAT_CONF_DIR, container)
}

// GetConfHome returns configuration directory
func (p *FilebeatPiloter) GetConfHome() string {
	return FILEBEAT_CONF_DIR
}

// Name returns plugin name
func (p *FilebeatPiloter) Name() string {
	return p.name
}

// OnDestroyEvent watching destroy event
func (p *FilebeatPiloter) OnDestroyEvent(container string) error {
	return p.feed(container)
}

// GetBaseConf returns plugin root directory
func (p *FilebeatPiloter) GetBaseConf() string {
	return FILEBEAT_BASE_CONF
}
