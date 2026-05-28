from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


APP_NAME = "Backend Transaccional"
TOKEN_TTL_SECONDS = int(os.getenv("TOKEN_TTL_SECONDS", "86400"))
TOKEN_SECRET = os.getenv("TOKEN_SECRET", "change-me-in-production")
PASSWORD_ITERATIONS = int(os.getenv("PASSWORD_ITERATIONS", "210000"))


def _build_cors_origins() -> list[str]:
	raw_origins = os.getenv("CORS_ALLOW_ORIGINS", "*").strip()
	if not raw_origins:
		return ["*"]
	return [origin.strip() for origin in raw_origins.split(",") if origin.strip()]


def _build_database_url() -> str:
	database_url = os.getenv("DATABASE_URL")
	if database_url:
		return database_url

	mysql_user = os.getenv("MYSQL_USER")
	mysql_password = os.getenv("MYSQL_PASSWORD")
	mysql_host = os.getenv("MYSQL_HOST")
	mysql_port = os.getenv("MYSQL_PORT", "3306")
	mysql_database = os.getenv("MYSQL_DATABASE")

	if mysql_user and mysql_password and mysql_host and mysql_database:
		return (
			f"mysql+pymysql://{mysql_user}:{mysql_password}@{mysql_host}:{mysql_port}/{mysql_database}"
		)

	return os.getenv("SQLITE_URL", "sqlite:///./backend_transaccional.db")


DATABASE_URL = _build_database_url()


engine_kwargs: dict[str, Any] = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
	engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
	pass


class Usuario(Base):
	__tablename__ = "usuarios"

	id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
	nombre: Mapped[str] = mapped_column(String(120), nullable=False)
	email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
	password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

	hilos: Mapped[list["Hilo"]] = relationship(
		back_populates="usuario",
		cascade="all, delete-orphan",
	)


class Hilo(Base):
	__tablename__ = "hilos"

	id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
	usuario_id: Mapped[int] = mapped_column(ForeignKey("usuarios.id", ondelete="CASCADE"), nullable=False, index=True)
	contenido_texto: Mapped[str] = mapped_column(Text, nullable=False)
	fecha_creacion: Mapped[datetime] = mapped_column(
		DateTime(timezone=True),
		nullable=False,
		default=lambda: datetime.now(timezone.utc),
	)

	usuario: Mapped[Usuario] = relationship(back_populates="hilos")


Base.metadata.create_all(bind=engine)


class UsuarioRegister(BaseModel):
	nombre: str | None = Field(default=None, min_length=2, max_length=120)
	email: EmailStr
	password: str = Field(min_length=8, max_length=128)


class UsuarioLogin(BaseModel):
	email: EmailStr
	password: str = Field(min_length=8, max_length=128)


class HiloCreate(BaseModel):
	contenido_texto: str = Field(min_length=1, max_length=5000)


class HiloUpdate(BaseModel):
	contenido_texto: str = Field(min_length=1, max_length=5000)


class UsuarioOut(BaseModel):
	model_config = ConfigDict(from_attributes=True)

	id: int
	nombre: str
	email: EmailStr


class HiloOut(BaseModel):
	model_config = ConfigDict(from_attributes=True)

	id: int
	usuario_id: int
	contenido_texto: str
	fecha_creacion: datetime
	autor: UsuarioOut


class LoginResponse(BaseModel):
	access_token: str
	token_type: str = "bearer"
	usuario: UsuarioOut


class MessageResponse(BaseModel):
	message: str


app = FastAPI(title=APP_NAME, version="1.0.0")

CORS_ALLOW_ORIGINS = _build_cors_origins()
CORS_ALLOW_CREDENTIALS = os.getenv("CORS_ALLOW_CREDENTIALS", "false").lower() == "true"

app.add_middleware(
	CORSMiddleware,
	allow_origins=CORS_ALLOW_ORIGINS,
	allow_credentials=CORS_ALLOW_CREDENTIALS,
	allow_methods=["*"],
	allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def http_exception_handler(_, exc: HTTPException):
	return JSONResponse(
		status_code=exc.status_code,
		content={
			"ok": False,
			"error": {
				"code": exc.status_code,
				"message": exc.detail,
			},
		},
	)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError):
	return JSONResponse(
		status_code=status.HTTP_400_BAD_REQUEST,
		content={
			"ok": False,
			"error": {
				"code": status.HTTP_400_BAD_REQUEST,
				"message": "Datos de entrada inválidos",
				"details": exc.errors(),
			},
		},
	)


@app.exception_handler(Exception)
async def unhandled_exception_handler(_, exc: Exception):
	return JSONResponse(
		status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
		content={
			"ok": False,
			"error": {
				"code": status.HTTP_500_INTERNAL_SERVER_ERROR,
				"message": "Error interno del servidor",
			},
		},
	)


def get_db() -> Generator[Session, None, None]:
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


def _hash_password(password: str, salt: Optional[bytes] = None) -> str:
	salt_bytes = salt or secrets.token_bytes(16)
	password_hash = hashlib.pbkdf2_hmac(
		"sha256",
		password.encode("utf-8"),
		salt_bytes,
		PASSWORD_ITERATIONS,
	)
	return f"{base64.urlsafe_b64encode(salt_bytes).decode('ascii')}${base64.urlsafe_b64encode(password_hash).decode('ascii')}"


def _verify_password(password: str, stored_hash: str) -> bool:
	try:
		salt_b64, hash_b64 = stored_hash.split("$", 1)
		salt = base64.urlsafe_b64decode(salt_b64.encode("ascii"))
		expected = base64.urlsafe_b64decode(hash_b64.encode("ascii"))
	except (ValueError, base64.binascii.Error):
		return False

	candidate = hashlib.pbkdf2_hmac(
		"sha256",
		password.encode("utf-8"),
		salt,
		PASSWORD_ITERATIONS,
	)
	return hmac.compare_digest(candidate, expected)


def _create_token(user_id: int) -> str:
	issued_at = int(time.time())
	payload = f"{user_id}.{issued_at}"
	signature = hmac.new(
		TOKEN_SECRET.encode("utf-8"),
		payload.encode("utf-8"),
		hashlib.sha256,
	).hexdigest()
	return f"{payload}.{signature}"


def _decode_token(token: str) -> int:
	try:
		user_id_str, issued_at_str, signature = token.split(".", 2)
		payload = f"{user_id_str}.{issued_at_str}"
		expected_signature = hmac.new(
			TOKEN_SECRET.encode("utf-8"),
			payload.encode("utf-8"),
			hashlib.sha256,
		).hexdigest()
		if not hmac.compare_digest(signature, expected_signature):
			raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")

		issued_at = int(issued_at_str)
		if time.time() - issued_at > TOKEN_TTL_SECONDS:
			raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado")

		return int(user_id_str)
	except ValueError as exc:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido") from exc


def get_current_user(
	authorization: str | None = Header(default=None, alias="Authorization"),
	db: Session = Depends(get_db),
) -> Usuario:
	if not authorization or not authorization.startswith("Bearer "):
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Autenticación requerida")

	token = authorization.removeprefix("Bearer ").strip()
	user_id = _decode_token(token)
	user = db.get(Usuario, user_id)
	if not user:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario no encontrado")
	return user


def _usuario_to_out(usuario: Usuario) -> UsuarioOut:
	return UsuarioOut.model_validate(usuario)


def _hilo_to_out(hilo: Hilo) -> HiloOut:
	return HiloOut(
		id=hilo.id,
		usuario_id=hilo.usuario_id,
		contenido_texto=hilo.contenido_texto,
		fecha_creacion=hilo.fecha_creacion,
		autor=_usuario_to_out(hilo.usuario),
	)


@app.get("/health", response_model=MessageResponse)
def healthcheck() -> dict[str, str]:
	return {"message": "API funcionando correctamente"}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(usuario_data: UsuarioRegister, db: Session = Depends(get_db)) -> JSONResponse:
	existing_user = db.scalar(select(Usuario).where(Usuario.email == usuario_data.email))
	if existing_user:
		raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="El email ya está registrado")

	nombre = usuario_data.nombre.strip() if usuario_data.nombre else usuario_data.email.split("@", 1)[0]
	nombre = nombre[:120]

	usuario = Usuario(
		nombre=nombre,
		email=usuario_data.email.lower(),
		password_hash=_hash_password(usuario_data.password),
	)

	try:
		db.add(usuario)
		db.commit()
		db.refresh(usuario)
	except IntegrityError as exc:
		db.rollback()
		raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No se pudo registrar el usuario") from exc
	except SQLAlchemyError as exc:
		db.rollback()
		raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error al registrar el usuario") from exc

	return JSONResponse(
		status_code=status.HTTP_201_CREATED,
		content={
			"ok": True,
			"message": "Usuario registrado correctamente",
			"data": _usuario_to_out(usuario).model_dump(mode="json"),
		},
	)


@app.post("/auth/login", response_model=LoginResponse)
def login(credentials: UsuarioLogin, db: Session = Depends(get_db)) -> JSONResponse:
	usuario = db.scalar(select(Usuario).where(Usuario.email == credentials.email.lower()))
	if not usuario or not _verify_password(credentials.password, usuario.password_hash):
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")

	access_token = _create_token(usuario.id)
	return JSONResponse(
		status_code=status.HTTP_200_OK,
		content={
			"ok": True,
			"message": "Autenticación exitosa",
			"data": LoginResponse(
				access_token=access_token,
				usuario=_usuario_to_out(usuario),
			).model_dump(mode="json"),
		},
	)


@app.get("/hilos")
def listar_hilos(db: Session = Depends(get_db), _: Usuario = Depends(get_current_user)) -> JSONResponse:
	hilos = db.scalars(
		select(Hilo).order_by(Hilo.fecha_creacion.desc(), Hilo.id.desc())
	).all()

	payload = [_hilo_to_out(hilo).model_dump(mode="json") for hilo in hilos]
	return JSONResponse(
		status_code=status.HTTP_200_OK,
		content={
			"ok": True,
			"message": "Hilos obtenidos correctamente",
			"data": payload,
		},
	)


@app.post("/hilos", status_code=status.HTTP_201_CREATED)
def crear_hilo(
	hilo_data: HiloCreate,
	db: Session = Depends(get_db),
	current_user: Usuario = Depends(get_current_user),
) -> JSONResponse:
	hilo = Hilo(
		usuario_id=current_user.id,
		contenido_texto=hilo_data.contenido_texto.strip(),
		fecha_creacion=datetime.now(timezone.utc),
	)

	try:
		db.add(hilo)
		db.commit()
		db.refresh(hilo)
		db.refresh(hilo, attribute_names=["usuario"])
	except SQLAlchemyError as exc:
		db.rollback()
		raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo crear el hilo") from exc

	return JSONResponse(
		status_code=status.HTTP_201_CREATED,
		content={
			"ok": True,
			"message": "Hilo creado correctamente",
			"data": _hilo_to_out(hilo).model_dump(mode="json"),
		},
	)


@app.put("/hilos/{hilo_id}")
def editar_hilo(
	hilo_id: int,
	hilo_data: HiloUpdate,
	db: Session = Depends(get_db),
	current_user: Usuario = Depends(get_current_user),
) -> JSONResponse:
	hilo = db.get(Hilo, hilo_id)
	if not hilo:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hilo no encontrado")

	if hilo.usuario_id != current_user.id:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No puedes editar este hilo")

	hilo.contenido_texto = hilo_data.contenido_texto.strip()

	try:
		db.commit()
		db.refresh(hilo)
		db.refresh(hilo, attribute_names=["usuario"])
	except SQLAlchemyError as exc:
		db.rollback()
		raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo editar el hilo") from exc

	return JSONResponse(
		status_code=status.HTTP_200_OK,
		content={
			"ok": True,
			"message": "Hilo actualizado correctamente",
			"data": _hilo_to_out(hilo).model_dump(mode="json"),
		},
	)


@app.delete("/hilos/{hilo_id}")
def eliminar_hilo(
	hilo_id: int,
	db: Session = Depends(get_db),
	current_user: Usuario = Depends(get_current_user),
) -> JSONResponse:
	hilo = db.get(Hilo, hilo_id)
	if not hilo:
		raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Hilo no encontrado")

	if hilo.usuario_id != current_user.id:
		raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No puedes eliminar este hilo")

	try:
		db.delete(hilo)
		db.commit()
	except SQLAlchemyError as exc:
		db.rollback()
		raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="No se pudo eliminar el hilo") from exc

	return JSONResponse(
		status_code=status.HTTP_200_OK,
		content={
			"ok": True,
			"message": "Hilo eliminado correctamente",
			"data": None,
		},
	)


if __name__ == "__main__":
	import uvicorn

	uvicorn.run(
		"main:app",
		host=os.getenv("HOST", "0.0.0.0"),
		port=int(os.getenv("PORT", "8000")),
		reload=os.getenv("RELOAD", "true").lower() == "true",
	)
