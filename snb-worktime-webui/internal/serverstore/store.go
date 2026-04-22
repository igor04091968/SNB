package serverstore

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"snb-worktime-webui/internal/model"
)

type Store struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) List() ([]model.LinuxServer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	servers, err := s.load()
	if err != nil {
		return nil, err
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Name == servers[j].Name {
			return servers[i].Host < servers[j].Host
		}
		return servers[i].Name < servers[j].Name
	})
	return sanitize(servers), nil
}

func (s *Store) Upsert(server model.LinuxServer) (model.LinuxServer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	servers, err := s.load()
	if err != nil {
		return model.LinuxServer{}, err
	}

	server.Name = strings.TrimSpace(server.Name)
	server.Host = strings.TrimSpace(server.Host)
	server.Username = strings.TrimSpace(server.Username)
	server.Notes = strings.TrimSpace(server.Notes)
	if server.Name == "" || server.Host == "" || server.Username == "" {
		return model.LinuxServer{}, fmt.Errorf("name, host, and username are required")
	}
	if server.Port <= 0 {
		server.Port = 22
	}

	now := time.Now().UTC()
	if server.ID == "" {
		server.ID = generateID()
		server.CreatedAt = now
		server.UpdatedAt = now
		servers = append(servers, server)
	} else {
		found := false
		for index := range servers {
			if servers[index].ID != server.ID {
				continue
			}
			preserveSecretFields(&server, servers[index])
			server.CreatedAt = servers[index].CreatedAt
			server.UpdatedAt = now
			servers[index] = server
			found = true
			break
		}
		if !found {
			server.CreatedAt = now
			server.UpdatedAt = now
			servers = append(servers, server)
		}
	}

	if err := s.save(servers); err != nil {
		return model.LinuxServer{}, err
	}
	return sanitizeOne(server), nil
}

func preserveSecretFields(next *model.LinuxServer, existing model.LinuxServer) {
	if next == nil {
		return
	}
	if strings.TrimSpace(next.Password) == "" {
		next.Password = existing.Password
	}
	if strings.TrimSpace(next.PrivateKeyPEM) == "" {
		next.PrivateKeyPEM = existing.PrivateKeyPEM
	}
	if strings.TrimSpace(next.PrivateKeyPassphrase) == "" {
		next.PrivateKeyPassphrase = existing.PrivateKeyPassphrase
	}
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	servers, err := s.load()
	if err != nil {
		return err
	}

	filtered := servers[:0]
	for _, server := range servers {
		if server.ID != id {
			filtered = append(filtered, server)
		}
	}

	return s.save(filtered)
}

func (s *Store) ByIDs(ids []string) ([]model.LinuxServer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	servers, err := s.load()
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return servers, nil
	}

	need := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		need[id] = struct{}{}
	}

	var out []model.LinuxServer
	for _, server := range servers {
		if _, ok := need[server.ID]; ok {
			out = append(out, server)
		}
	}
	return out, nil
}

func (s *Store) load() ([]model.LinuxServer, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []model.LinuxServer{}, nil
		}
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return []model.LinuxServer{}, nil
	}

	var servers []model.LinuxServer
	if err := json.Unmarshal(data, &servers); err != nil {
		return nil, err
	}
	return servers, nil
}

func (s *Store) save(servers []model.LinuxServer) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(servers, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, append(data, '\n'), 0o600)
}

func generateID() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

func sanitize(servers []model.LinuxServer) []model.LinuxServer {
	out := make([]model.LinuxServer, 0, len(servers))
	for _, server := range servers {
		out = append(out, sanitizeOne(server))
	}
	return out
}

func sanitizeOne(server model.LinuxServer) model.LinuxServer {
	server.Password = ""
	server.PrivateKeyPEM = ""
	server.PrivateKeyPassphrase = ""
	return server
}
