package hub

import (
	"mensageria_segura/internal/database"
	"sync/atomic"
)

type Session struct {
	dto     *database.Session
	recvSeq atomic.Uint64
	sendSeq atomic.Uint64
}

func NewSession(dto *database.Session) *Session {
	return &Session{
		dto: dto,
	}
}

func (s *Session) ID() int {
	return int(s.dto.ID)
}

func (s *Session) ClientID() string {
	return s.dto.ClientID
}

func (s *Session) NextSeq() uint64 {
	return s.sendSeq.Add(1)
}

func (s *Session) SendSeq() uint64 {
	return s.sendSeq.Load()
}

func (s *Session) RecvSeq() uint64 {
	return s.recvSeq.Load()
}

func (s *Session) AdvanceRecvSeq(seq uint64) bool {
	for {
		current := s.recvSeq.Load()
		if seq <= current {
			return false
		}
		if s.recvSeq.CompareAndSwap(current, seq) {
			return true
		}
	}
}

func (s *Session) DTO() *database.Session {
	return s.dto
}

func (s *Session) KeyPair() (KeyC2S []byte, KeyS2C []byte) {
	return s.dto.KeyC2S, s.dto.KeyS2C
}

func (s *Session) KeyC2S() []byte {
	return s.dto.KeyC2S
}

func (s *Session) KeyS2C() []byte {
	return s.dto.KeyS2C
}
