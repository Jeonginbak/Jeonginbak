# Login

<aside>
💡 로그인이 필요한 서비스를 이용할 때마다 아이디와 비번을 매번 적게하는 것은 불편하고 보안상 좋지 않기 때문에 로그인 시에 발급한 토큰(또는 세션)에 최소한의 사용자 식별정보를 담은 토큰으로 인증을 함으로써 개인정보의 유출을 예방할 수 있다.

</aside>

# Session, Token의 특징

- **Session과 Token(JWT)에 관한 글**
    
    ⭐  [Login을 위한 Session 와 Token 인증 개념](https://idlecomputer.tistory.com/239)
    
    ⭐  [세션 동작 원리 - 쿠키와 세션의 관계](https://thecodinglog.github.io/web/2020/08/11/what-is-session.html)
    
    ⭐  ****[[JWT] 토큰(Token) 기반 인증에 대한 소개](https://velopert.com/2350)
    

## 🧐 Session 방식(서버기반 인증)의 단점

- 로그인을 한 사용자의 정보를 session에 저장하게 될 경우 로그인 중인 사용자가 증가할 경우 서버 램의 과부하 우려가 있음.
- 서버를 확장하기가 어려워진다. Session ID가 저장된 서버로만 요청을 보내야한다. 분산 시스템 설계시 session ID의 공유를 구현하는 것이 불가능한 것은 아니지만 과정이 복잡하다.
- 세션을 사용시에 쿠키를 사용하게 되는데, 쿠키의 보안 취약점. 불필요한 네트워크 트래픽이 발생 할 수 있다.
- CORS문제 쿠키는 단일도메인, 서브도메인에서만 작동하도록 설계되어 있어 도메인관리가 번거롭다.

## 😃 Token 방식의 장점

- 모바일 애플리케이션에서 사용하기 좋다.
- 쿠키를 사용함으로써 발생하는 보안 취약점을 방지(토큰을 사용하는 환경에서도 보안의 취약점은 존재한다!)
- 토큰을 클라이언트 사이드에서 저장하기 때문에 서버는 무상태(stateless)를 유지할 수 있다.
- 서버 확장성이 좋다. 로그인의 여부가에 상관없이 서버확장이 가능하고 서버가 여러대가 되어도 토큰으로 로그인 했다면 어떤 서버로 요청이 가도 상관없다.
- 로그인 확장성이 좋다. 토큰에 권한을 부여하여 사용할 수 있기때문에 다양한 로그인 방식을 도입할 수 있다.(ex. sns 로그인)
- CORS문제에서 자유롭다. 토큰만 유효하면 어떤 도메인에서든지 처리할 수 있다. header에 `Access-Control-Allow-Origin: *` 만 포함 시키면 된다.

# Passport?

🔗  [Passport js docs](http://www.passportjs.org/docs/downloads/html/)

<aside>
💡 Passport is authentication middleware for Node. It is designed to serve a singular purpose: authenticate requests. When writing modules, encapsulation is a virtue, so Passport delegates all other functionality to the application. This separation of concerns keeps code clean and maintainable, and makes Passport extremely easy to integrate into an application.
Passport recognizes that each application has unique authentication requirements. Authentication mechanisms, known as strategies, are packaged as individual modules. Applications can choose which strategies to employ, without creating unnecessary dependencies.

</aside>

> Passport는 Nodejs용 인증 미들웨어이다. Passport를 선택함으로써 구현해야할 로그인 방식에 필요한 불필요한 종속성을 설치하지 않아도 된다.
> 

- 📔  **노드js교과서 ([익스프레스로 SNS 서비스 만들기](https://github.com/ZeroCho/nodejs-book/blob/master/ch9/9.5/nodebird/app.js))에 나온 Passport 구현 과정**
    - **주요 개념**
        
        ```jsx
        // app.js
        app.use(passport.initialize())
        app.use(passport.session())
        ```
        
        `**passport.initialize**`   req객체에 passport 설정을 저장
        
        `**passport.session`**   req.session(express-session)객체에 passport 정보를 저장 (passport 미들웨어는 express-session 미들웨어보다 뒤에 연결)
        
        ```jsx
        // index.js
        module.exports = () => {
        	passport.serializeUser((user, done) => {
        		done(null, user.id); // 첫번째 인수는 에러발생시, 두번째 인수는 저장하고 싶은 데이터
        	});
        
        	passport.deserializeUser((id, done) => {
        // serialzueUser의 두번째 인수가 매개 변수가 됨 (user.id)
        		User.findOne({ where: { id } }) // 데이터베이스에 유저 정보 조회
        			.then(user => done(null, user)) // 유저정보를 req에 저장
        			.catch(err => done(err));
        	})
        }
        ```
        
        `**passport.serializeUser`**   로그인시 실행 req.session 객체에 어떤 데이터를 저장할지 정하는 메서드
        세션에 많은 정보를 저장하면 세션의 용량이 커지고 데이터 일관성에 문제가 생길 수 있음. 그래서 사용자 아이디만 저장함.
        
        `**passport.deserializeUser`**   매 요청시 실행. passport.session 미들웨어가 이 메서드를 호출. serialze에서 세션에 저장했던 정보를 가지고 데이터베이스에서 사용자 정보를 조회하고 조회한 정보를 req.user에 저장한다. 앞으로 로그인 한 사용자 정보는 req.user를 통해 가져올 수 있다.
        
        > serialize는 유저정보를 세션에 저장, deserialize는 세션의 정보로를 가지고 사용자 객체를 불러옴(db) **세션에 불필요한 데이터를 담아두지 않기 위함**
        > 
        
        passport에서 로그인 시의 동적을 전략(Strategy)이라고 표현. 사용하고자하는 로그인 방식에 따른 전략파일을 만들어 줘야 함.
        
        ```jsx
        // localStrategy.js
        module.exports = () => {
          passport.use(new LocalStrategy({
        	// 전략에 관한 설정, 로그인 라우터의 req.body의 property
        	// (ex. req.body.email, req.body.password)
            usernameField: 'email',
            passwordField: 'password',
          }, async (email, password, done) => {
        		// 실제 전략을 수행하는 함수, 앞서 설정한 email, password를 넣는다
        		// done 함수는 passport.authenticate의 콜백 함수
        		// passport.authenticate('local', (authError, user, info)=> {})
        		// authError는 에러발생시, user는 로그인성공시 담기는 정보, info는 에러시 내보낼 message
            try {
              const exUser = await User.findOne({ where: { email } });
              if (exUser) {
                const result = await bcrypt.compare(password, exUser.password);
                if (result) {
                  done(null, exUser); //로그인 성공시
                } else {
                  done(null, false, { message: '비밀번호가 일치하지 않습니다.' });
                }
              } else {
                done(null, false, { message: '가입되지 않은 회원입니다.' });
              }
            } catch (error) {
              console.error(error);
              done(error);
            }
          }));
        };
        ```
        
         
        
    - **로그인 과정**
        1. 라우터를 통해 로그인 요청이 들어옴
        2. 라우터에서 passport.authenicate 메서드 호출
        3. 로그인 전략 수행(Strategy)
        4. 로그인 성공 시 사용자 정보 객체와 함께 req.login 호출
        5. req.login 메서드가 passport.serializeUser 호출
        6. req.session에 사용자 아이디만 저장
        7. 로그인 완료
    
    - **로그인 이후**
        1. 요청이 들어옴
        2. 라우터에 요청이 도달하기 전에 passport.session 미들웨어가 passport.deserializeUser 메서드 호출
        3. req.session에 저장된 아이디로 데이터베이스에서 사용자 조회
        4. 조회된 사용자 정보를 req.user에 저장
        5. 라우터에서 req.user 객체 사용 가능
        
    - **PassPort Login 구현 추가 예제**
        
        ⭐  [패스포트 동작 원리와 인증 구현](https://jeonghwan-kim.github.io/dev/2020/06/20/passport.html)
        

## 😯 Passport-local과 Passport-jwt 방식의 차이점

Passport local은 Session 방식으로 인증, Passport JWT는 JWT를 이용한 토큰 인증 방식(Bearer Token)이다. 이외에도 여러가지 차이점이 있으나 크게 중요하진 않다!

- Passport local 와 Passport JWT의 차이점을 설명한 글
    
    [Difference Between Passport and Passport JWT (With Table)](https://askanydifference.com/difference-between-passport-and-passport-jwt/)
    

# Refresh Token 기반 인증

## 🎬 Refresh Token 기반 인증 시나리오([RFC6749](https://datatracker.ietf.org/doc/html/rfc6749))

![Login%2010d20e921b4d42f280c74d021a983c10/Untitled.png](Login%2010d20e921b4d42f280c74d021a983c10/Untitled.png)

```
(A) Client에서 Authorization Server로 인증 부여(Authorization Grant) 요청

(B) Authorization Server에서 Client로 Access Token & Refresh Token 전송(인증 부여)

(C) Client에서 Access Token으로 Resource Server에서 보호된 리소스(Protected Resource)에 
    접근을 요청

(D) **Case 1** Resource Server에서 Token을 검증하고 보호된 리소스(Protected Resource)를 
    Client에 전송

(E) (C)와 동일

(F) **Case 2** Resource Server에서 Token을 검증함. 토큰이 유효하지 않음. 
    Invalid Token Error를 Client에 전송

(G) Client에서 Refresh Token으로 Authorization Server로 Acess Token을 재발급 요청

(H) Authorization Server에서 Refresh Token을 검증후 유효하면 Access Token을 
    Client에 발급(Refresh Token 재발급은 선택(optional))
```

## 🧩 JWT 보안 알고리즘에 대해

- [참고] JWT handbook
    
    [jwt-handbook-v0_14_1.pdf](Login%2010d20e921b4d42f280c74d021a983c10/jwt-handbook-v0_14_1.pdf)
    
    HMAC algorithms rely on a shared secret to produce and verify signatures. Some people assume that shared secrets are similar to passwords, and in a sense, they are: they should be kept secret. However, that is where the similarities end. For passwords, although the length is an important property, the minimum required length is relatively small compared to other types of secrets. This is a consequence of the hashing algorithms that are used to store passwords (along with a salt) that prevent brute force attacks in reasonable timeframes.
    
    [On the other hand, HMAC shared secrets, as used by JWTs, are optimized for speed. This allows many sign/verify operations to be performed efficiently but make brute force attacks easier](notion://www.notion.so/monegishop/Passport-js-831f7c0133d24c27ba8f27834f761da1#bookmark329)8[. So, the length of the shared secret for HS256/384/512 is of the utmost importance. In fact, JSON Web Algorithms](notion://www.notion.so/monegishop/Passport-js-831f7c0133d24c27ba8f27834f761da1#bookmark330)9 defines the minimum key length to be equal to the size in bits of the hash function used along with the HMAC algorithm:
    
    [“A key of the same size as the hash output (for instance, 256 bits for”HS256“) or larger MUST be used with this algorithm.” - JSON Web Algorithms (RFC 7518), 3.2 HMAC with SHA-2 Functions10](notion://www.notion.so/monegishop/Passport-js-831f7c0133d24c27ba8f27834f761da1#bookmark331)
    
    [In other words, many passwords that could be used in other contexts are simply not good enough for use with HMAC-signed JWTs. 256-bits equals 32 ASCII characters, so if you are using something human readable, consider that number to be the minimum number of characters to include in the secret. Another good option is to switch to RS256 or other public-key algorithms, which are much more robust and flexible. This is not simply a hypothetical attack, it has been shown that brute force attacks for HS256 are simple enough to perform](notion://www.notion.so/monegishop/Passport-js-831f7c0133d24c27ba8f27834f761da1#bookmark332)11 if the shared secret is too short.
    
- ⭐  [JWT를 소개합니다.](https://meetup.toast.com/posts/239)
    
    
- 기본 알고리즘은 HS256이며 Secret_key는 길이는 256bit 이상으로 설정한다.
- RS256 알고리즘을 사용하는 경우는 클라이언트에서 JWT의 서명을 검증해야할 때 사용하게 된다.
(공개키 암호화 알고리즘)
    - 📚  관련 글
        
        ⭐  [RS256, HS256 차이](https://hwannny.tistory.com/72)
        
        ⭐  [Navigating RS256 and JWKS](https://auth0.com/blog/navigating-rs256-and-jwks/)
        

## 🔑 Bearer Token([RFC 6750](https://datatracker.ietf.org/doc/html/rfc6750))

> OAuth 2.0 API에서 인증하는 가장 일반적인 방법
> 
- RFC 6750 Bearer Token 소개
    
    ```
    OAuth enables clients to access protected resources by obtaining an
    access token, which is defined in "The OAuth 2.0 Authorization
    Framework" [RFC6749] as "a string representing an access
    authorization issued to the client", rather than using the resource
    owner's credentials directly.
    ```
    
- Bearer Token의 장.단점
    
    OAuth 1에는 액세스 토큰에 대한 두 가지 구성 요소 인 공개 및 비공개 문자열이 있습니다. 개인 문자열은 요청에 서명 할 때 사용되며 유선을 통해 전송되지 않습니다.
    
    OAuth 2.0 API에 액세스하는 가장 일반적인 방법은 "Bearer Token"을 사용하는 것입니다. 이것은 HTTP "Authorization"헤더로 전송되는 API 요청의 인증 역할을하는 단일 문자열입니다. 문자열은 사용하는 클라이언트에게 의미가 없으며 길이가 다를 수 있습니다.
    
    Bearer 토큰은 각 요청의 암호화 서명이 필요하지 않기 때문에 API 요청을 만드는 훨씬 간단한 방법입니다. 단점은 모든 API 요청이 HTTPS 연결을 통해 이루어져야한다는 것입니다. 요청에는 가로 채면 누구나 사용할 수있는 일반 텍스트 토큰이 포함되어 있기 때문입니다. 장점은 요청을 만들기 위해 복잡한 라이브러리가 필요하지 않으며 클라이언트와 서버 모두 구현하기가 훨씬 간단하다는 것입니다.
    
    Bearer 토큰의 단점은 다른 앱이 Bearer 토큰에 액세스 할 수있는 경우 사용하는 것을 방해하는 것이 없다는 것입니다. 대부분의 공급자는 어쨌든 Bearer 토큰 만 사용하지만 이것은 OAuth 2.0에 대한 일반적인 비판입니다. 정상적인 상황에서 응용 프로그램이 제어하에 액세스 토큰을 적절하게 보호하면 기술적으로는 덜 안전하지만 문제가되지 않습니다. 서비스에보다 안전한 접근 방식이 필요한 경우 보안 요구 사항을 충족 할 수있는 다른 액세스 토큰 유형을 사용할 수 있습니다.
    
    ⭐ [[원문] Bearer Tokens](https://www.oauth.com/oauth2-servers/differences-between-oauth-1-2/bearer-tokens/)
    
- 📚  관련 글
    
    ⭐  [[StackOverFlow] What is the OAuth 2.0 Bearer Token exactly?](https://stackoverflow.com/questions/25838183/what-is-the-oauth-2-0-bearer-token-exactly/25843058)
    
    ⭐  [What is Bearer token and How it works?](https://www.devopsschool.com/blog/what-is-bearer-token-and-how-it-works/)
    

## ♻️ Refresh Token 기반 인증 Login 시나리오

- ✨  **시나리오 설계에 도움 받은 예제**
    
    ⭐ [[Node.js] JWT: Access Token & Refresh Token 인증 구현](https://cotak.tistory.com/102)
    
    ⭐ [서버 인증(JWT)](https://brownbears.tistory.com/440)
    
    ⭐ [https://github.com/EricKit/nest-user-auth](https://github.com/EricKit/nest-user-auth)
    

### Login 요청

1. Client에서 LogIn 요청 (Email, Password)
2. Server는 Client에서 받은 User 정보(Email, Password)로 User 검증
    
    → **`True`** Access Token과 Refresh Token을 발급
    이때, Access Token과 Refresh Token이 가지고 있는 정보는 동일하고 만료시간만 다르다.
    Access Token은 짧게 Refresh Token은 길게 설정해 놓는다.
    
    → **`False`** User 정보가 존재하지 않으므로 Authentication Error 전송
    

### Access Token으로 리소스 접근

1. Client에서 Access Token으로 리소스 접근 요청
2. Server는 Client에서 받은 Access Token의 유효성 검증
    
    → **`True`** Access Token이 유효함으로 리소스를 Client에 전달
    
    → **`False`** Access Token이 유효하지 않음. Client에 Authentication Error 전송
    

### Refresh Token으로 Access Token 재발급 요청

1. Client에서 Refresh Token 전송
    
    ‼️  Refresh Token, Access Token 둘다 받는 것으로 변경. [참고](https://develoger.kr/grphql%EC%9D%84-%EC%82%AC%EC%9A%A9%ED%95%98%EB%8A%94-frontend%EC%97%90%EC%84%9C-jwt%EB%8B%A4%EB%A3%A8%EA%B8%B0/)
    
2. Server에서 Refresh Token의 유효성을 검증
    
    → **`Case 1`** Refresh Token이 유효함 → Access Token만 재발급해서 Client에 전송
    
    → **`Case 2`** Refresh Token이 유효하지 않음 → Refresh Token과 Access Token을 재발급
    
    ‼️ Case 1이 생길 때마다 Refresh Token도 같이 재발급하는 부분에 대해서 고민해봐야 할 것 같습니다. 위의 RFC 6749 문서에서 볼 수 있듯이  Access token발급시 Refresh Token도 같이 발급하게 할 수 있습니다(선택사항임).
    
    ‼️ Case 2  Refresh Token이 만료시 Authentication Error를 Client에 전송하고 다시 로그인하게 해야한다는 의견을 보았는데 타당한 의견 같다고 생각합니다. 실제 프로젝트 구현시 이렇게 변경해야한다고 생각합니다. [↩️]()
    

### Logout 요청

- Client에서 Access Token(또는 Refresh Token) 전송
- Server에서는 User 정보로 저장되어 있는 Refresh Token을 찾아 삭제하고 Client에 결과 전송
    
    → **`True`** Client에서는 저장소에 있는 Token들을 모두 삭제
    
    → **`False`** 케이스 생각을 해봐야함
    

# nestjs에서 Passport-jwt를 활용한 구현

## 🔐 nestjs Login Project

### **Project ERD**

![Login%2010d20e921b4d42f280c74d021a983c10/Untitled%201.png](Login%2010d20e921b4d42f280c74d021a983c10/Untitled%201.png)

### 사용한 패키지

⚠️  ****로그인에 관련된 패키지만 설명

- `**@nestjs/jwt`**  jwt의 사용을 간편하게 해줍니다.(secret key, expeiredIn의 global 설정)
- **`@nestjs/passport`**  passport의 다양한 Strategy를 편리하고 심플하게 사용하게 해주고, guard를 내장하여 validation도 같이 해줍니다.
- `**passport, passport-jwt**`  @nestjs/passport의 의존성을 위해 설치

### Architecture

```
.
├── app.module.ts
├── domain
│   ├── auth
│   │   ├── dto
│   │   │   ├── auth.input.ts
│   │   │   └── auth.output.ts
│   │   ├── entity
│   │   │   └── refresh-token.entity.ts
│   │   ├── guard
│   │   │   └── jwt-auth.guard.ts
│   │   ├── interface
│   │   │   └── payload.interface.ts
│   │   ├── resolver
│   │   │   └── auth.resolver.ts
│   │   ├── service
│   │   │   └── auth.service.ts
│   │   └── strategy
│   │       └── jwt.strategy.ts
│   └── user
│       ├── entity
│       │   └── user.entity.ts
│       ├── interface
│       │   └── user.interface.ts
│       ├── resolver
│       └── service
│           └── user.service.ts
├── injector.module.ts
└── main.ts

14 directories, 14 files
```

### **Flow: 로그인한 유저가 인증이 필요한 리소스에 접근 시**

- **`me`** 는 현재 로그인한 유저를 확인할 수 있는 API이다.
1. Client에서 **`me`** API를 요청한다.
2. app.module의 graphql module에서 context에 request를 넣어준다.
3. JwtAuthGuard에서 getRequest함수를 통해 http context를 graphql에서 사용할 수 있도록 graphql context로 변경한다.
4. JwtStergy에서 request headers의 Authrization에서 bearer token을 추출해서 decode 한다.
(context - request - headers - authrization)
    
    3-1 validate 함수로 decode된 user id로 user 정보를 찾아서 user를 반환한다.
    
5. JwtAuthGuard의 handleRequest 함수에서 user 정보를 받아서 반환한다.
6. AuthGuard에서 user를 context에 넣는다.
7. AuthResolver **`me`** API에서 context에서 user를 추출해서 응답한다.
    
    (user를 꺼내서 sevice에서 필요한 로직을 처리 후 응답할 수도 있다. ex> [logoutByEmailUser]())
    

```tsx
@Query(type => User)
  @UseGuards(JwtAuthGuard)
	// getRequest와 handleRequest에서 context를 통한 user를 받을 수 있게 한다.
  me(@Context("req") request: any) {
    const user = request.user;
    return user;
  }
```

### Project Code 설명

`**injector.module.ts`**  ⚠️  ****로그인에 관련된 설정만 설명

- PassportModule에서 기본 전략으로 jwt를 사용하고, 세션을 사용하지 않음을 설정
- JwtModule에서 secret key와 expiresIn의 글로벌로 설정할 수 있음 secret key는 env 파일로 관리되기 때문에 이를 가져오기위해 nestjs configsevice를 사용하여 가져옴
    - [useFactory에 대한 nestjs docs](https://docs.nestjs.com/fundamentals/custom-providers#factory-providers-usefactory)
- JwtStrategy가 nestjs내의 프로젝트에서 사용되기 위해 provider를 등록해준다.

```tsx
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtModule, JwtModuleOptions, JwtService } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { JwtStrategy } from "./domain/auth/strategy/jwt.strategy";

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: "jwt", session: false }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => {
        const options: JwtModuleOptions = {
          secret: configService.get("JWT_SECRET"),
        };
        options.signOptions = {
          expiresIn: "60s",
        };
        return options;
      },
      inject: [ConfigService],
    }),
    ConfigModule,
  ],
  providers: [JwtStrategy],
})
export class InjectorModule {}
```

‼️ `app.module.ts`에서 관리하는게 맞는 것 같아 후에 프로젝트에서는 변경 예정

**`jwt-auth.guard.ts`**

- @nestjs/passport의 AuthGuard를 상속하여 사용한다. REST API 방식을 사용할 경우에는 AuthGuard를 상속해 주기만 하면 된다.
- graphql의 경우에는 `getRequest()` 함수에서 context를 받아서 graphql conext로 변경해 준다.
- 별도의 핸들링(err)이 필요한 경우에는 `handleRequest()` 함수를 통해 설정할 수 있다.

```tsx
import { Injectable } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { GqlExecutionContext } from "@nestjs/graphql";
import { ExecutionContext } from "@nestjs/common";
import { AuthenticationError } from "apollo-server-express";

@Injectable()
export class JwtAuthGuard extends AuthGuard("jwt") {
  getRequest(context: ExecutionContext) {
    const ctx = GqlExecutionContext.create(context);
    const request = ctx.getContext().req;
    return request;
  }

  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      throw err || new AuthenticationError("Could not authenticate with token");
    }
    return user;
  }
}
```

`**jwt.strategy.ts**`

- jwtFromRequest,  secretOrKey → header에서 bearer token을 추출해 decode한다.
- validate → decode한 정보로 user를 조회해서 user 정보를 반환한다.

```tsx
import { ExtractJwt, Strategy } from "passport-jwt";
import { PassportStrategy } from "@nestjs/passport";
import { Injectable } from "@nestjs/common";
import { UserService } from "src/domain/user/service/user.service";
import { AuthenticationError } from "apollo-server-express";
import { Payload } from "../interface/payload.interface";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly userService: UserService,
    private readonly configService: ConfigService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get("JWT_SECRET"),
    });
  }
  async validate(payload: Payload) {
    const user = await this.userService.findUserById(payload.id);

    if (!user) {
      throw new AuthenticationError("유저가 존재하지 않습니다");
    }
    return user;
  }
}
```

**`auth.service.ts`/ `auth.resolver.ts`**

**issueToken**

- 토큰 발급을 담당하는 함수. 토큰 발급 유형을 세가지로 나눠서 상황에 맞게 토큰을 발급한다.
    - **new**: access token과 refresh token을 모두 생성하고 db에 refresh token을 저장한다.
    - **reIssue**: refresh token과 access token을 모두 재발급 하고 refresh token을 업데이트 한다.
    - **reAccess**: refresh token이 유효하면 access token만 발급한다.

```tsx
//auth.service.ts
async issueToken(user: User, issueType: "new" | "reIssue" | "reAcess"): Promise<TokenOutput> {
    const payload = { userId: user.id };
    const refreshTokenExpTime = 86400 * 7; // 1 day = 86400

    switch (issueType) {
      case "new": {
        const refreshToken = this.jwtService.sign(payload, { expiresIn: refreshTokenExpTime });
        const accessToken = this.jwtService.sign(payload);
        await this.refreshToken.save(this.refreshToken.create({ user, token: refreshToken }));
        return {
          accessToken,
          refreshToken,
        };
      }

      case "reIssue": {
        const refreshToken = this.jwtService.sign(payload, { expiresIn: refreshTokenExpTime });
        const accessToken = this.jwtService.sign(payload);
        await this.refreshToken.update({ user }, { token: refreshToken });
        return {
          accessToken,
          refreshToken,
        };
      }

      case "reAccess": {
        return { accessToken: this.jwtService.sign(payload) };
      }
    }
  }
```

**LoginByEmailUser**

- 로그인을 담당하는 함수 Client로부터 받은 user의 email과 password를 확인해서 토큰을 발급한다.
- 일치하는 유저가 있으면 db에 refresh token이 저장되어 있는지 확인한다.
    
    → 있는 경우 토큰을 재발급한다.(reissue)
    
    - unique column으로 validation 하지 않는 이유
        
        refresh token entity(table)을 만들 때 column type을 unique 설정을 해두면 별도의 validation이 필요하지 않지만 이 경우 type orm query error(dup entry err)로 처리 됨. 문제가 있는 것은 아니지만 catch에서 err에 대한 핸들링이 되는데도 콘솔에 error 메세지가 띄워져서 정상적으로 처리 됬음에도 error로 보여 미리 validation 하는 것으로 변경
        
    
    → 없는 경우 토큰을 생성한다.(new)
    

```tsx
//auth.service.ts
async LoginByEmailUser({ email, password }: LoginInput): Promise<TokenOutput> {
    const user = await this.userService.validUserByEmail(email);
    if (!user) throw Error("email을 확인해 주세요");

    try {
      if (email === user.email && password === user.password) {
        const isExists = await this.refreshToken.findOne({ user });
        if (isExists) return await this.issueToken(user, "reIssue");
        return await this.issueToken(user, "new");
      }
    } catch (err) {
      throw Error(`LoginByEmailUser Err => ${err.message}`);
    }
  }
```

```tsx
//auth.resolver.ts
@Mutation(type => TokenOutput)
  async loginByEmailUser(@Args() input: LoginInput): Promise<TokenOutput> {
    return await this.authService.LoginByEmailUser(input);
  }
```

**reissueToken**

- refreshToken을 받아서 유효한 토큰인지 검증한다
    
    → token이 유효할 경우 access token만 재발급 한다.
    
    → token이 유효하지 않은 경우  token을 decode해서 user 정보를 확인 후 재발급한다.
    
    😒  [이 케이스는 변경이 필요함]()
    

```tsx
//auth.service.ts
async reissueToken(refreshToken: string): Promise<TokenOutput> {
		//받는 인자로 user, refreshToken, accessToken이렇게 세개를 받아야함.
		//토큰에 있는 user 정보와 context의 user 정보가 일치하는지 확인
    try {
      const tokenVerified: any = this.jwtService.verify(refreshToken);
      const user = await this.userService.findUserById(tokenVerified.userId);
			// 이 api를 보내는 user의 상태는 로그인을 한 상태임
			// 이 로직 삭제 context에 user 정보가 있으므로 그 정보로 확인
		
      return await this.issueToken(user, "reAcess");
    } catch (err) {
      const decoded: any = this.jwtService.decode(refreshToken);
      if (!decoded) throw Error(`${err.name} : ${err.message}`);

      const user = await this.userService.findUserById(decoded.id);
      if (!user) throw Error(`user가 존재하지 않습니다`);
			// 이 api를 보내는 user의 상태는 로그인을 한 상태임
			// 이 로직 삭제 context에 user 정보가 있으므로 그 정보로 확인
      return await this.issueToken(user, "reIssue");
    }
  }
```

- context에서 bearer token을 추출하고 token앞의 bearer라는 문자를 제거해서 service에 요청해야한다.

```json
//headers에 있는 authorization token
{ "authorization": "Bearer token_string" }
```

```tsx
//auth.resolver.ts
@Mutation(type => TokenOutput)
  async reissueToken(@Context("req") req: any): Promise<TokenOutput> {
    const token = req.headers.authorization.split(" ")[1];
    return await this.authService.reissueToken(token);
  
```

**logoutByEmailUser**

- client에서 요청이 오면 user 정보를 context에서 꺼내서 db에서 해당 user의 refresh token을 삭제한다.
    
    ‼️  user(req.user), refresh token(req.headers. authorization) 중 무엇으로 확인하는 게 맞는지 고민
    
    → 유저로부터 refreshToken을 받고 1. db에서 일치하는 refreshToken을 찾고 2. 가지고 있는 user fk id가 context user id와 일치하는 지 확인. 결론 : 클라이언트에서 refresh token을 받아야한다. 
    
- 삭제 완료후 Client에 결과를 반환한다.

```tsx
//auth.service.ts
async logoutByEmailUser(user: User): Promise<boolean>{
    const deleteToken = await this.refreshToken.delete({ user })
    return deleteToken.affected ? true : false
  }
```

- request의 user를 변수에 담아 sevice에 요청한다.

```tsx
//auth.resolver.ts
@Mutation(type => Boolean)
  @UseGuards(JwtAuthGuard)
  async logoutByEmailUser(@Context("req") req: any): Promise<boolean> {
    const user = request.user;
    return await this.authService.logoutByEmailUser(user);
  }
```

[↩️]()
