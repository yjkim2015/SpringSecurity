package io.security.basicsecurity;

import java.io.IOException;
import java.nio.file.AccessDeniedException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

//@Configuration 
//@EnableWebSecurity
public class SecurityConfig_2 extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
		auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
		auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");

	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests() //http 방식으로 요청을 할 때 보안검사
			//.antMatchers("/shop/**")
			.antMatchers("/login").permitAll()
			.antMatchers("/user").hasRole("USER")
			.antMatchers("/admin/pay").access("hasRole('ADMIN')")
			.antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")

			.anyRequest() //어떤 요청이든
			.authenticated() //인증 받도록 
			.and() 
			.formLogin() //폼 로그인방식을 통해 인증 방식 제공
			//.loginPage("/loginPage")  // 로그인 페이지
			.defaultSuccessUrl("/") //기본 성공 URL
			.failureUrl("/login") // 실패 URL
			.usernameParameter("userId") // 기본 user Parameter 세팅
			.passwordParameter("passwd") // 기본 passwd Parameter 세팅
			.loginProcessingUrl("/login_proc") //로그인 과정 프로세스 url
			.successHandler(new AuthenticationSuccessHandler() {
				//로그인 성공 시 Handler
				@Override
				public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
						Authentication authentication) throws IOException, ServletException {
						/*이전 요청에 성공한 url로 들어간다*/
						RequestCache requestCache = new HttpSessionRequestCache();
						SavedRequest savedRequest = requestCache.getRequest(request, response);
						String redirectUrl = savedRequest.getRedirectUrl();
						response.sendRedirect(redirectUrl);
				}
			})
			.failureHandler(new AuthenticationFailureHandler() {
				//로그인 실패 시 Handler
				@Override
				public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
						AuthenticationException exception) throws IOException, ServletException {
					System.out.println("exception : " + exception);
					response.sendRedirect("/login");
				}
			})
			.permitAll();
		http.logout()
			.logoutUrl("/logout")
			.logoutSuccessUrl("/login")
			.addLogoutHandler(new LogoutHandler() {
				
				@Override
				public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
					HttpSession session = request.getSession();
					session.invalidate();
				}
			})
			.logoutSuccessHandler(new LogoutSuccessHandler() {
				
				@Override
				public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
						throws IOException, ServletException {
					response.sendRedirect("/login");
				}
			})
			.deleteCookies("remember-me");
		
		http.rememberMe()
			.rememberMeParameter("remember") // 기본 파라미터 명은 
			.tokenValiditySeconds(3600) //토큰 만료 시간 기본 14일
			//.alwaysRemember(true) // 리멤버 미 기능이 활성화 되지 않아도 항상 실행
			.userDetailsService(userDetailsService); // 유저계정을 조회하는 과정을 처리하는 부분 
		
		http.sessionManagement() //세션관리 기능이 작동함
		.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
		.sessionFixation().none() //기본값 // none, migrationSession, newSession
		.maximumSessions(1) // 최대 세션 수
		.maxSessionsPreventsLogin(false) // 동시 로그인 차단 기본 false : 기존 세션만료 
		.expiredUrl("/expired"); //세션이 만료된 경우 이동 할 페이지
		

		
		http
			.exceptionHandling()  
			.authenticationEntryPoint(new AuthenticationEntryPoint() {
				//인증실패시 처리
				@Override
				public void commence(HttpServletRequest request, HttpServletResponse response,
						AuthenticationException authException) throws IOException, ServletException {
					response.sendRedirect("/login");
				}
			} ) 
			.accessDeniedHandler(new AccessDeniedHandler() {
				//인가실패시 처리
				@Override
				public void handle(HttpServletRequest request, HttpServletResponse response,
						org.springframework.security.access.AccessDeniedException accessDeniedException)
						throws IOException, ServletException {
					response.sendRedirect("/denied");
				}
			});
			
	}
	
}
