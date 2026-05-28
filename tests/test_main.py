from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient


TEMP_DIR = Path(tempfile.mkdtemp(prefix="backend_transaccional_tests_"))
DATABASE_PATH = TEMP_DIR / "test.db"

os.environ["DATABASE_URL"] = f"sqlite:///{DATABASE_PATH.as_posix()}"
os.environ["TOKEN_SECRET"] = "test-secret"
os.environ["TOKEN_TTL_SECONDS"] = "3600"
os.environ["PASSWORD_ITERATIONS"] = "1000"

main = importlib.import_module("main")


class ApiRoutesTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        main.Base.metadata.drop_all(bind=main.engine)
        main.Base.metadata.create_all(bind=main.engine)
        cls.client = TestClient(main.app)

    def register_user(self, email: str, nombre: str | None = None) -> dict:
        payload = {
            "email": email,
            "password": "Password123!",
        }
        if nombre is not None:
            payload["nombre"] = nombre

        response = self.client.post("/auth/register", json=payload)
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertTrue(body["ok"])
        return body["data"]

    def login_user(self, email: str) -> str:
        response = self.client.post(
            "/auth/login",
            json={"email": email, "password": "Password123!"},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["ok"])
        return body["data"]["access_token"]

    def auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def test_healthcheck(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "API funcionando correctamente"})

    def test_register_without_nombre(self) -> None:
        email = f"{uuid4().hex[:12]}@example.com"
        user = self.register_user(email)

        self.assertEqual(user["email"], email)
        self.assertEqual(user["nombre"], email.split("@", 1)[0])

    def test_register_with_nombre(self) -> None:
        email = f"{uuid4().hex[:12]}@example.com"
        user = self.register_user(email, nombre="Usuario Demo")

        self.assertEqual(user["email"], email)
        self.assertEqual(user["nombre"], "Usuario Demo")

    def test_register_duplicate_email(self) -> None:
        email = f"{uuid4().hex[:12]}@example.com"
        self.register_user(email)

        response = self.client.post(
            "/auth/register",
            json={
                "email": email,
                "password": "Password123!",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_login_with_valid_credentials(self) -> None:
        email = f"{uuid4().hex[:12]}@example.com"
        self.register_user(email)

        token = self.login_user(email)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 10)

    def test_login_with_invalid_credentials(self) -> None:
        email = f"{uuid4().hex[:12]}@example.com"
        self.register_user(email)

        response = self.client.post(
            "/auth/login",
            json={"email": email, "password": "WrongPassword123!"},
        )
        self.assertEqual(response.status_code, 401)

    def test_hilos_requires_authentication(self) -> None:
        response = self.client.get("/hilos")
        self.assertEqual(response.status_code, 401)

    def test_hilo_crud_flow(self) -> None:
        email = f"{uuid4().hex[:12]}@example.com"
        self.register_user(email)
        token = self.login_user(email)
        headers = self.auth_headers(token)

        create_response = self.client.post(
            "/hilos",
            json={"contenido_texto": "Primer hilo"},
            headers=headers,
        )
        self.assertEqual(create_response.status_code, 201)
        hilo = create_response.json()["data"]

        list_response = self.client.get("/hilos", headers=headers)
        self.assertEqual(list_response.status_code, 200)
        self.assertGreaterEqual(len(list_response.json()["data"]), 1)

        update_response = self.client.put(
            f"/hilos/{hilo['id']}",
            json={"contenido_texto": "Hilo actualizado"},
            headers=headers,
        )
        self.assertEqual(update_response.status_code, 200)
        self.assertEqual(update_response.json()["data"]["contenido_texto"], "Hilo actualizado")

        delete_response = self.client.delete(f"/hilos/{hilo['id']}", headers=headers)
        self.assertEqual(delete_response.status_code, 200)

        list_after_delete = self.client.get("/hilos", headers=headers)
        self.assertEqual(list_after_delete.status_code, 200)
        self.assertEqual(list_after_delete.json()["data"], [])

    def test_hilo_edit_and_delete_rejects_foreign_user(self) -> None:
        owner_email = f"{uuid4().hex[:12]}@example.com"
        foreign_email = f"{uuid4().hex[:12]}@example.com"

        self.register_user(owner_email)
        self.register_user(foreign_email)

        owner_token = self.login_user(owner_email)
        foreign_token = self.login_user(foreign_email)

        create_response = self.client.post(
            "/hilos",
            json={"contenido_texto": "Contenido privado"},
            headers=self.auth_headers(owner_token),
        )
        hilo_id = create_response.json()["data"]["id"]

        edit_response = self.client.put(
            f"/hilos/{hilo_id}",
            json={"contenido_texto": "Intento ajeno"},
            headers=self.auth_headers(foreign_token),
        )
        self.assertEqual(edit_response.status_code, 401)

        delete_response = self.client.delete(
            f"/hilos/{hilo_id}",
            headers=self.auth_headers(foreign_token),
        )
        self.assertEqual(delete_response.status_code, 401)


if __name__ == "__main__":
    unittest.main()