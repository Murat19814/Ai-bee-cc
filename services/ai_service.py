"""
AI BEE CC - AI Service Layer
Comprehensive AI services for call center operations
"""

import os
import json
import asyncio
from datetime import datetime, date
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass
from enum import Enum

# AI Provider abstraction
class AIProviderType(Enum):
    STT = "stt"
    TTS = "tts"
    LLM = "llm"
    EMBEDDING = "embedding"


@dataclass
class TranscriptionResult:
    """STT sonucu"""
    text: str
    segments: List[Dict]
    confidence: float
    language: str
    duration: float
    word_timestamps: Optional[List[Dict]] = None


@dataclass
class AnalysisResult:
    """Çağrı analiz sonucu"""
    summary: str
    sentiment: str
    sentiment_score: float
    topics: List[str]
    keywords: List[str]
    intent: str
    issues: List[Dict]
    next_action: str
    crm_suggestions: Dict


@dataclass
class QAResult:
    """QA değerlendirme sonucu"""
    total_score: float
    percentage: float
    passed: bool
    criteria_scores: List[Dict]
    strengths: List[str]
    weaknesses: List[str]
    violations: List[Dict]
    coaching_suggestions: List[str]


class AIService:
    """Ana AI Servis Sınıfı"""
    
    def __init__(self, app=None):
        self.app = app
        self.stt_providers = {}
        self.tts_providers = {}
        self.llm_providers = {}
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Flask app ile başlat"""
        self.app = app
        self._load_providers()
    
    def _load_providers(self):
        """AI sağlayıcılarını yükle"""
        # Whisper STT
        self.stt_providers['whisper'] = WhisperSTTProvider()
        
        # OpenAI
        self.llm_providers['openai'] = OpenAILLMProvider()
        
        # ElevenLabs TTS
        self.tts_providers['elevenlabs'] = ElevenLabsTTSProvider()
    
    # ==========================================
    # STT - Speech to Text
    # ==========================================
    
    async def transcribe_call(
        self,
        audio_path: str,
        language: str = "tr",
        provider: str = "whisper",
        model: str = "base"
    ) -> TranscriptionResult:
        """Çağrı kaydını metne dönüştür"""
        
        stt = self.stt_providers.get(provider)
        if not stt:
            raise ValueError(f"Unknown STT provider: {provider}")
        
        result = await stt.transcribe(audio_path, language, model)
        return result
    
    def transcribe_call_sync(
        self,
        audio_path: str,
        language: str = "tr",
        provider: str = "whisper",
        model: str = "base"
    ) -> TranscriptionResult:
        """Senkron transkripsiyon"""
        return asyncio.run(self.transcribe_call(audio_path, language, provider, model))
    
    # ==========================================
    # TTS - Text to Speech
    # ==========================================
    
    async def synthesize_speech(
        self,
        text: str,
        language: str = "tr",
        voice_id: str = None,
        provider: str = "elevenlabs"
    ) -> bytes:
        """Metni sese dönüştür"""
        
        tts = self.tts_providers.get(provider)
        if not tts:
            raise ValueError(f"Unknown TTS provider: {provider}")
        
        audio_data = await tts.synthesize(text, language, voice_id)
        return audio_data
    
    # ==========================================
    # Call Analysis
    # ==========================================
    
    async def analyze_call(
        self,
        transcript: str,
        context: Dict = None,
        provider: str = "openai"
    ) -> AnalysisResult:
        """Çağrı transkriptini analiz et"""
        
        llm = self.llm_providers.get(provider)
        if not llm:
            raise ValueError(f"Unknown LLM provider: {provider}")
        
        # Analiz promptu
        prompt = self._build_analysis_prompt(transcript, context)
        
        response = await llm.complete(prompt, temperature=0.3)
        result = self._parse_analysis_response(response)
        
        return result
    
    def _build_analysis_prompt(self, transcript: str, context: Dict = None) -> str:
        """Analiz promptu oluştur"""
        
        context_str = ""
        if context:
            context_str = f"""
Bağlam Bilgileri:
- Kampanya: {context.get('campaign_name', 'Bilinmiyor')}
- Müşteri Segmenti: {context.get('customer_segment', 'Bilinmiyor')}
- Önceki Etkileşimler: {context.get('previous_interactions', 0)}
"""
        
        return f"""
Aşağıdaki çağrı merkezi görüşme transkriptini analiz et ve JSON formatında yanıt ver.

{context_str}

GÖRÜŞME TRANSKRİPTİ:
{transcript}

ANALİZ TALİMATLARI:
1. Görüşmenin kısa özetini çıkar
2. Genel duygu durumunu belirle (positive, neutral, negative)
3. Konuşulan ana konuları listele
4. Anahtar kelimeleri çıkar
5. Müşteri niyetini tespit et (şikayet, bilgi, satın alma, iptal vb.)
6. Tespit edilen sorunları listele (varsa)
7. Önerilen sonraki aksiyonu belirle
8. CRM için önerilen alan güncellemelerini çıkar

JSON FORMATI:
{{
    "summary": "...",
    "sentiment": "positive|neutral|negative",
    "sentiment_score": 0.0, // -1 ile 1 arası
    "topics": ["konu1", "konu2"],
    "keywords": ["kelime1", "kelime2"],
    "intent": "...",
    "issues": [
        {{"type": "...", "description": "...", "severity": "low|medium|high"}}
    ],
    "next_action": "callback|email|escalate|close|follow_up",
    "crm_suggestions": {{
        "customer_segment": "...",
        "satisfaction_level": "...",
        "churn_risk": "low|medium|high"
    }}
}}
"""
    
    def _parse_analysis_response(self, response: str) -> AnalysisResult:
        """Analiz yanıtını parse et"""
        try:
            # JSON bloğunu bul
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            
            data = json.loads(json_str)
            
            return AnalysisResult(
                summary=data.get('summary', ''),
                sentiment=data.get('sentiment', 'neutral'),
                sentiment_score=float(data.get('sentiment_score', 0)),
                topics=data.get('topics', []),
                keywords=data.get('keywords', []),
                intent=data.get('intent', ''),
                issues=data.get('issues', []),
                next_action=data.get('next_action', ''),
                crm_suggestions=data.get('crm_suggestions', {})
            )
        except Exception as e:
            return AnalysisResult(
                summary="Analiz yapılamadı",
                sentiment="neutral",
                sentiment_score=0,
                topics=[],
                keywords=[],
                intent="unknown",
                issues=[],
                next_action="",
                crm_suggestions={}
            )
    
    # ==========================================
    # QA Evaluation
    # ==========================================
    
    async def evaluate_call_qa(
        self,
        transcript: str,
        criteria: List[Dict],
        context: Dict = None,
        provider: str = "openai"
    ) -> QAResult:
        """Çağrıyı QA kriterlerine göre değerlendir"""
        
        llm = self.llm_providers.get(provider)
        if not llm:
            raise ValueError(f"Unknown LLM provider: {provider}")
        
        prompt = self._build_qa_prompt(transcript, criteria, context)
        response = await llm.complete(prompt, temperature=0.2)
        result = self._parse_qa_response(response, criteria)
        
        return result
    
    def _build_qa_prompt(
        self,
        transcript: str,
        criteria: List[Dict],
        context: Dict = None
    ) -> str:
        """QA değerlendirme promptu"""
        
        criteria_str = "\n".join([
            f"- {c['name']} (Max: {c['max_points']} puan, Kritik: {'Evet' if c.get('is_critical') else 'Hayır'}): {c.get('description', '')}"
            for c in criteria
        ])
        
        return f"""
Aşağıdaki çağrı merkezi görüşmesini verilen QA kriterlerine göre değerlendir.

GÖRÜŞME TRANSKRİPTİ:
{transcript}

DEĞERLENDİRME KRİTERLERİ:
{criteria_str}

DEĞERLENDİRME TALİMATLARI:
1. Her kriteri 0'dan maksimum puana kadar değerlendir
2. Güçlü yönleri belirle
3. Gelişim alanlarını belirle
4. İhlalleri tespit et (yasaklı kelime, KVKK ihlali vb.)
5. Koçluk önerileri sun

YASAKLI KELİMELER KONTROLÜ:
- Küfür, hakaret
- Agresif veya tehditkar ifadeler
- Yanıltıcı bilgi verme
- KVKK ihlali (izinsiz veri paylaşımı)

JSON FORMATI:
{{
    "criteria_scores": [
        {{"criteria_name": "...", "score": X, "max": Y, "reasoning": "..."}}
    ],
    "total_score": X,
    "max_possible": Y,
    "percentage": X.X,
    "passed": true|false,
    "strengths": ["..."],
    "weaknesses": ["..."],
    "violations": [
        {{"type": "forbidden_word|aggressive|kvkk", "severity": "low|medium|high|critical", "details": "..."}}
    ],
    "coaching_suggestions": ["..."]
}}
"""
    
    def _parse_qa_response(self, response: str, criteria: List[Dict]) -> QAResult:
        """QA yanıtını parse et"""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            json_str = response[json_start:json_end]
            
            data = json.loads(json_str)
            
            return QAResult(
                total_score=float(data.get('total_score', 0)),
                percentage=float(data.get('percentage', 0)),
                passed=data.get('passed', False),
                criteria_scores=data.get('criteria_scores', []),
                strengths=data.get('strengths', []),
                weaknesses=data.get('weaknesses', []),
                violations=data.get('violations', []),
                coaching_suggestions=data.get('coaching_suggestions', [])
            )
        except Exception:
            return QAResult(
                total_score=0,
                percentage=0,
                passed=False,
                criteria_scores=[],
                strengths=[],
                weaknesses=[],
                violations=[],
                coaching_suggestions=[]
            )
    
    # ==========================================
    # Real-time Agent Assist
    # ==========================================
    
    async def get_agent_suggestion(
        self,
        current_text: str,
        context: Dict,
        suggestion_type: str = "all",
        provider: str = "openai"
    ) -> Dict:
        """Gerçek zamanlı agent önerisi al"""
        
        llm = self.llm_providers.get(provider)
        if not llm:
            raise ValueError(f"Unknown LLM provider: {provider}")
        
        prompt = f"""
Çağrı merkezi agentına gerçek zamanlı öneri sun.

MEVCUT KONUŞMA:
{current_text}

BAĞLAM:
- Kampanya: {context.get('campaign_name', '')}
- Script: {context.get('script_name', '')}
- Müşteri: {context.get('customer_name', '')}

ÖNERİ TİPİ: {suggestion_type}

Uygun bir öneri sun:
1. script: Script'ten ilgili bölüm
2. objection: İtiraz karşılama önerisi
3. upsell: Çapraz satış fırsatı
4. compliance: Uyum uyarısı
5. knowledge: Bilgi tabanından yanıt

JSON formatında yanıt ver:
{{
    "suggestion_type": "...",
    "suggestion_text": "...",
    "confidence": 0.0-1.0,
    "context": "Neden bu öneri?"
}}
"""
        
        response = await llm.complete(prompt, temperature=0.3, max_tokens=500)
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            return json.loads(response[json_start:json_end])
        except:
            return {
                "suggestion_type": "none",
                "suggestion_text": "",
                "confidence": 0,
                "context": ""
            }
    
    # ==========================================
    # Sentiment Analysis
    # ==========================================
    
    async def analyze_sentiment(
        self,
        text: str,
        provider: str = "openai"
    ) -> Tuple[str, float]:
        """Duygu analizi yap"""
        
        llm = self.llm_providers.get(provider)
        if not llm:
            return "neutral", 0.0
        
        prompt = f"""
Aşağıdaki metni analiz et ve duygu durumunu belirle.

METİN:
{text}

JSON formatında yanıt ver:
{{
    "sentiment": "positive|neutral|negative",
    "score": -1.0 ile 1.0 arası,
    "reasoning": "..."
}}
"""
        
        response = await llm.complete(prompt, temperature=0.1, max_tokens=200)
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            data = json.loads(response[json_start:json_end])
            return data.get('sentiment', 'neutral'), float(data.get('score', 0))
        except:
            return "neutral", 0.0
    
    # ==========================================
    # Lead Scoring
    # ==========================================
    
    async def score_lead(
        self,
        lead_data: Dict,
        historical_data: Dict = None,
        provider: str = "openai"
    ) -> Dict:
        """Lead skorla"""
        
        llm = self.llm_providers.get(provider)
        if not llm:
            return {"score": 50, "probability": 0.5}
        
        prompt = f"""
Aşağıdaki lead bilgilerini değerlendir ve satış potansiyelini skorla.

LEAD BİLGİLERİ:
{json.dumps(lead_data, ensure_ascii=False, indent=2)}

GEÇMİŞ VERİLER:
{json.dumps(historical_data or {}, ensure_ascii=False, indent=2)}

JSON formatında yanıt ver:
{{
    "overall_score": 0-100,
    "conversion_probability": 0.0-1.0,
    "best_time_to_call": {{"day": "...", "hour": X}},
    "recommended_approach": "...",
    "scoring_factors": [
        {{"factor": "...", "impact": "+X veya -X", "explanation": "..."}}
    ]
}}
"""
        
        response = await llm.complete(prompt, temperature=0.2, max_tokens=500)
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            return json.loads(response[json_start:json_end])
        except:
            return {
                "overall_score": 50,
                "conversion_probability": 0.5,
                "best_time_to_call": {"day": "weekday", "hour": 10},
                "recommended_approach": "Standard yaklaşım",
                "scoring_factors": []
            }
    
    # ==========================================
    # KVKK Compliance Check
    # ==========================================
    
    def check_kvkk_compliance(
        self,
        transcript: str,
        required_phrases: List[str] = None
    ) -> Dict:
        """KVKK uyumluluğunu kontrol et"""
        
        default_phrases = [
            "aydınlatma metni",
            "ses kaydı",
            "onay",
            "kabul",
            "kişisel veri"
        ]
        
        phrases_to_check = required_phrases or default_phrases
        transcript_lower = transcript.lower()
        
        found_phrases = []
        missing_phrases = []
        
        for phrase in phrases_to_check:
            if phrase.lower() in transcript_lower:
                found_phrases.append(phrase)
            else:
                missing_phrases.append(phrase)
        
        compliance_score = len(found_phrases) / len(phrases_to_check) if phrases_to_check else 1.0
        
        return {
            "is_compliant": compliance_score >= 0.8,
            "compliance_score": compliance_score,
            "found_phrases": found_phrases,
            "missing_phrases": missing_phrases,
            "recommendations": [
                f"'{phrase}' ifadesi kullanılmalı" for phrase in missing_phrases
            ]
        }
    
    # ==========================================
    # Forbidden Words Detection
    # ==========================================
    
    def detect_forbidden_words(
        self,
        text: str,
        forbidden_words: List[str] = None
    ) -> List[Dict]:
        """Yasaklı kelimeleri tespit et"""
        
        default_forbidden = [
            "salak", "aptal", "gerizekalı", "mal", "ahmak",
            "siktir", "amk", "aq",
            "yalan söylüyorsun", "dolandırıcı"
        ]
        
        words_to_check = forbidden_words or default_forbidden
        text_lower = text.lower()
        
        violations = []
        
        for word in words_to_check:
            word_lower = word.lower()
            if word_lower in text_lower:
                # Pozisyonu bul
                pos = text_lower.find(word_lower)
                violations.append({
                    "word": word,
                    "position": pos,
                    "context": text[max(0, pos-20):pos+len(word)+20],
                    "severity": "critical" if any(c in word_lower for c in ["siktir", "amk"]) else "high"
                })
        
        return violations
    
    # ==========================================
    # Knowledge Base (RAG)
    # ==========================================
    
    async def query_knowledge_base(
        self,
        question: str,
        knowledge_base_id: int,
        top_k: int = 3,
        provider: str = "openai"
    ) -> Dict:
        """Bilgi tabanından sorgula (RAG)"""
        
        # Bu fonksiyon gerçek bir embedding ve vector search implementasyonu gerektirir
        # Şimdilik placeholder
        
        return {
            "answer": "Bilgi tabanı yanıtı burada olacak",
            "sources": [],
            "confidence": 0.0
        }
    
    # ==========================================
    # Smart Routing
    # ==========================================
    
    async def get_routing_recommendation(
        self,
        caller_number: str,
        customer_data: Dict = None,
        call_reason: str = None,
        available_queues: List[Dict] = None,
        available_agents: List[Dict] = None,
        provider: str = "openai"
    ) -> Dict:
        """Akıllı yönlendirme önerisi al"""
        
        llm = self.llm_providers.get(provider)
        if not llm:
            return {"queue_id": None, "agent_id": None, "priority": 0}
        
        prompt = f"""
Gelen çağrı için en uygun yönlendirmeyi belirle.

ARAYAN: {caller_number}

MÜŞTERİ BİLGİLERİ:
{json.dumps(customer_data or {}, ensure_ascii=False, indent=2)}

ÇAĞRI NEDENİ: {call_reason or 'Bilinmiyor'}

MEVCUT KUYRUKLAR:
{json.dumps(available_queues or [], ensure_ascii=False, indent=2)}

MEVCUT AGENTLAR:
{json.dumps(available_agents or [], ensure_ascii=False, indent=2)}

En uygun yönlendirmeyi JSON olarak belirle:
{{
    "recommended_queue_id": X veya null,
    "recommended_agent_id": X veya null,
    "priority_boost": 0-10,
    "is_vip": true|false,
    "urgency": "low|medium|high|critical",
    "reasoning": "..."
}}
"""
        
        response = await llm.complete(prompt, temperature=0.2, max_tokens=300)
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            return json.loads(response[json_start:json_end])
        except:
            return {
                "recommended_queue_id": None,
                "recommended_agent_id": None,
                "priority_boost": 0,
                "is_vip": False,
                "urgency": "medium",
                "reasoning": ""
            }


# ==========================================
# Provider Implementations
# ==========================================

class WhisperSTTProvider:
    """Whisper STT Provider"""
    
    def __init__(self):
        self.model = None
    
    async def transcribe(
        self,
        audio_path: str,
        language: str = "tr",
        model_name: str = "base"
    ) -> TranscriptionResult:
        """Whisper ile transkripsiyon"""
        
        try:
            import whisper
            
            if self.model is None or self.model_name != model_name:
                self.model = whisper.load_model(model_name)
                self.model_name = model_name
            
            result = self.model.transcribe(
                audio_path,
                language=language,
                word_timestamps=True
            )
            
            segments = []
            for seg in result.get('segments', []):
                segments.append({
                    "start": seg['start'],
                    "end": seg['end'],
                    "text": seg['text'],
                    "speaker": "unknown"  # Diarization için ayrı işlem gerekir
                })
            
            return TranscriptionResult(
                text=result['text'],
                segments=segments,
                confidence=0.9,  # Whisper doesn't provide confidence
                language=language,
                duration=segments[-1]['end'] if segments else 0,
                word_timestamps=None
            )
            
        except ImportError:
            # Whisper yüklü değilse placeholder
            return TranscriptionResult(
                text="[Whisper kurulu değil]",
                segments=[],
                confidence=0,
                language=language,
                duration=0
            )
        except Exception as e:
            return TranscriptionResult(
                text=f"[Transkripsiyon hatası: {str(e)}]",
                segments=[],
                confidence=0,
                language=language,
                duration=0
            )


class OpenAILLMProvider:
    """OpenAI LLM Provider"""
    
    def __init__(self):
        self.api_key = os.getenv('OPENAI_API_KEY')
        self.client = None
    
    async def complete(
        self,
        prompt: str,
        temperature: float = 0.3,
        max_tokens: int = 2000,
        model: str = "gpt-4"
    ) -> str:
        """OpenAI completion"""
        
        try:
            from openai import AsyncOpenAI
            
            if self.client is None:
                self.client = AsyncOpenAI(api_key=self.api_key)
            
            response = await self.client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "Sen bir çağrı merkezi AI asistanısın. Türkçe yanıt ver."},
                    {"role": "user", "content": prompt}
                ],
                temperature=temperature,
                max_tokens=max_tokens
            )
            
            return response.choices[0].message.content
            
        except ImportError:
            # OpenAI yüklü değilse mock yanıt
            return self._mock_response(prompt)
        except Exception as e:
            return f"[LLM Hatası: {str(e)}]"
    
    def _mock_response(self, prompt: str) -> str:
        """API yokken mock yanıt"""
        if "analiz" in prompt.lower():
            return json.dumps({
                "summary": "Demo özet - OpenAI API anahtarı gerekli",
                "sentiment": "neutral",
                "sentiment_score": 0,
                "topics": ["demo"],
                "keywords": ["test"],
                "intent": "unknown",
                "issues": [],
                "next_action": "follow_up",
                "crm_suggestions": {}
            })
        elif "qa" in prompt.lower() or "değerlendir" in prompt.lower():
            return json.dumps({
                "criteria_scores": [],
                "total_score": 75,
                "max_possible": 100,
                "percentage": 75,
                "passed": True,
                "strengths": ["Demo"],
                "weaknesses": [],
                "violations": [],
                "coaching_suggestions": []
            })
        else:
            return json.dumps({
                "message": "Demo yanıt - OpenAI API anahtarı gerekli"
            })


class ElevenLabsTTSProvider:
    """ElevenLabs TTS Provider"""
    
    def __init__(self):
        self.api_key = os.getenv('ELEVENLABS_API_KEY')
    
    async def synthesize(
        self,
        text: str,
        language: str = "tr",
        voice_id: str = None
    ) -> bytes:
        """ElevenLabs ile ses sentezi"""
        
        try:
            import httpx
            
            default_voice = voice_id or "21m00Tcm4TlvDq8ikWAM"  # Rachel
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"https://api.elevenlabs.io/v1/text-to-speech/{default_voice}",
                    headers={
                        "xi-api-key": self.api_key,
                        "Content-Type": "application/json"
                    },
                    json={
                        "text": text,
                        "model_id": "eleven_multilingual_v2",
                        "voice_settings": {
                            "stability": 0.5,
                            "similarity_boost": 0.75
                        }
                    }
                )
                
                if response.status_code == 200:
                    return response.content
                else:
                    return b""
                    
        except Exception:
            return b""


# Singleton instance
ai_service = AIService()

