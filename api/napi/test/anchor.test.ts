import { test, describe, it } from 'node:test';
import assert from 'node:assert';
import { plus100, napiGenerateAnchor, Secret } from '../index.js'; // 빌드된 JS 파일 import

const N = 6;
const K = 3;

describe('NAPI Module Tests', () => {
  
  // 2. 구조체(Struct) 전달 및 앵커 생성 테스트
  it('napiGenerateAnchor should process secrets and return anchors', () => {

    let mockSecret: Secret = {
        aud: "test_audience",
        iss: "test_issuer",
        sub: "test_subject",
    };

    // 테스트용 더미 데이터 생성
    const mockSecrets: Secret[] = Array(N).fill(mockSecret);

    console.log('Input Secrets:', mockSecrets);

    // 함수 호출
    const result = napiGenerateAnchor({ secrets: mockSecrets });

    console.log('Output Anchor:', result);

    // 검증 (Assertion)
    assert.ok(result, 'Result should not be null or undefined');
    assert.ok(Array.isArray(result.anchor), 'Anchor should be an array');
    assert.strictEqual(result.anchor.length, N - K + 1, `Anchor array length should be ${N - K + 1}`); 
    
    // 로직에 따라 다르겠지만, 입력 개수만큼 결과가 나온다고 가정한다면:
    
    // 결과값이 문자열인지 확인
    if (result.anchor.length > 0) {
      assert.strictEqual(typeof result.anchor[0], 'string', 'Anchor elements should be strings');
    }
  });
});