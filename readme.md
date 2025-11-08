HOW TO TEST FLOW

1️⃣ Start both apps:

mvn spring-boot:run -f auth-server/pom.xml
mvn spring-boot:run -f resource-server/pom.xml


2️⃣ Open browser and request authorization code:

http://localhost:9000/oauth2/authorize?response_type=code&client_id=my-client&redirect_uri=http://127.0.0.1:8081/login/oauth2/code/my-client&scope=read


3️⃣ Login → Copy authorization code from redirect URL

4️⃣ Exchange code for token (via Postman):

POST http://localhost:9000/oauth2/token
Form-data:
grant_type=authorization_code
code=<your-code>
redirect_uri=http://127.0.0.1:8081/login/oauth2/code/my-client
client_id=my-client
client_secret=my-secret


You’ll get back:

{
"access_token": "eyJraWQiOiJ...",
"token_type": "Bearer",
"expires_in": 300
}


5️⃣ Use the access token to call the resource server:

GET http://localhost:8081/secure
Authorization: Bearer <access_token>


✅ Output:

Welcome, user! You accessed a protected resource.