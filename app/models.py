from pydantic import BaseModel, Field

class ActivationRequest(BaseModel):
    key: str = Field(min_length=1, max_length=256)
    publicKey: str = Field(min_length=1, max_length=8192)

class ChallengeRequest(BaseModel):
    activationId: str = Field(min_length=1, max_length=256)

class VerificationRequest(BaseModel):
    activationId: str = Field(min_length=1, max_length=256)
    challengeId: str = Field(min_length=1, max_length=256)
    signature: str = Field(min_length=1, max_length=8192)
