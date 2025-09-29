package ds

func TestPaperVectors(t *testing.T){
  vecs := load("testdata/paper_vectors.json")
  okCnt := 0
  for _,v := range vecs {
     // 1) KeyGen 재현 → SK/PK 바이트 일치?
     // 2) Sign → Sig 바이트 일치?
     // 3) Verify → true/false 일치?
     // 4) 불일치 지점 로그
     if ... { okCnt++ }
  }
  t.Logf("match=%.2f%%", float64(okCnt)/float64(len(vecs))*100.0)
}
