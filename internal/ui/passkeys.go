package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/bnymnDev/agentgate/internal/passkey"
	"github.com/bnymnDev/agentgate/internal/proxy"
)

// Signing an answer asks the browser's authenticator twice over: begin hands
// out the options with the challenge bound to the approval, the answer and
// the arguments; finish checks the signature and only then answers. A deny
// needs no signature: refusing is always safe.

type passkeysData struct {
	page
	Enabled  bool
	Required bool
	Store    string
	Passkeys []passkey.Record
}

func (s *Server) handlePasskeys(w http.ResponseWriter, _ *http.Request) {
	d := &passkeysData{page: s.page("Passkeys", "approvals"), Enabled: s.opts.Passkeys != nil, Required: s.opts.PasskeysRequired}
	if s.opts.Passkeys != nil {
		d.Store = s.opts.Passkeys.Store().Path()
		list, err := s.opts.Passkeys.Store().List()
		if err != nil {
			s.fail(w, err)
			return
		}
		d.Passkeys = list
	}
	s.render(w, "passkeys", d)
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, err error) {
	writeJSONResponse(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	if s.opts.Passkeys == nil {
		jsonError(w, http.StatusNotFound, errors.New("passkeys are off; set approval.passkeys"))
		return
	}
	var in struct{ Name, Code string }
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	opts, key, err := s.opts.Passkeys.BeginEnroll(in.Name, in.Code)
	if err != nil {
		jsonError(w, http.StatusForbidden, err)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"key": key, "options": opts})
}

func (s *Server) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	if s.opts.Passkeys == nil {
		jsonError(w, http.StatusNotFound, errors.New("passkeys are off"))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	name, err := s.opts.Passkeys.FinishEnroll(r.URL.Query().Get("key"), body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	s.log.Info("passkey enrolled", "name", name)
	writeJSONResponse(w, http.StatusOK, map[string]string{"name": name})
}

// signTarget finds the approval and the answer a signature is for.
func (s *Server) signTarget(r *http.Request) (string, proxy.Choice, []byte, error) {
	if s.opts.Passkeys == nil || s.opts.Approvals == nil {
		return "", "", nil, errors.New("passkeys are off")
	}
	inbox, ok := s.opts.Approvals.(interface {
		Request(id string) (proxy.ApprovalRequest, bool)
	})
	if !ok {
		return "", "", nil, errors.New("this approvals queue cannot be signed")
	}
	id, choice := r.PathValue("id"), proxy.Choice(r.PathValue("verb"))
	switch choice {
	case proxy.ChoiceAllow, proxy.ChoiceAllowSession, proxy.ChoiceDeny:
	default:
		return "", "", nil, errors.New("expected allow, allow-session or deny")
	}
	req, ok := inbox.Request(id)
	if !ok {
		return "", "", nil, errors.New("this approval is no longer waiting")
	}
	return id, choice, req.Args, nil
}

func (s *Server) handleSignBegin(w http.ResponseWriter, r *http.Request) {
	id, choice, args, err := s.signTarget(r)
	if err != nil {
		jsonError(w, http.StatusNotFound, err)
		return
	}
	opts, err := s.opts.Passkeys.BeginSign(id, string(choice), args)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err)
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]any{"options": opts})
}

func (s *Server) handleSignFinish(w http.ResponseWriter, r *http.Request) {
	id, choice, _, err := s.signTarget(r)
	if err != nil {
		jsonError(w, http.StatusNotFound, err)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	signed, err := s.opts.Passkeys.FinishSign(id, string(choice), body)
	if err != nil {
		s.log.Warn("a signed approval did not verify", "approval", id, "error", err)
		jsonError(w, http.StatusForbidden, err)
		return
	}
	signer, ok := s.opts.Approvals.(interface {
		ResolveSigned(id string, choice proxy.Choice, passkey, evidence string) bool
	})
	if !ok {
		jsonError(w, http.StatusNotFound, errors.New("this approvals queue cannot take signed answers"))
		return
	}
	evidence := fmt.Sprintf("credential %s, signature %s", signed.Credential, signed.Evidence)
	if !signer.ResolveSigned(id, choice, signed.Name, evidence) {
		jsonError(w, http.StatusConflict, errors.New("this approval is no longer waiting, or this passkey answered it already"))
		return
	}
	s.log.Info("approval signed", "approval", id, "answer", choice, "passkey", signed.Name)
	writeJSONResponse(w, http.StatusOK, map[string]string{"by": signed.Name})
}
