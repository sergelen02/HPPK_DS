package cmd

type Vector struct {
  MsgHex string
  SK     struct{ F0,F1,H0,H1,R1,S1,R2,S2,Beta string }
  PK     struct{ Pprime, Qprime, Mu, Nu []string; S1p,S2p string }
  Sig    struct{ F,H string }
  VerifyOK bool
}
