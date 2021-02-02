package io.security.basicsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration 
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	UserDetailsService userDetailsService;
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests() //http 방식으로 요청을 할 때 보안검사
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
						System.out.println("authentication " + authentication.getName());
						response.sendRedirect("/");
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
		.maximumSessions(1) // 최대 세션 수
		.maxSessionsPreventsLogin(false) // 동시 로그인 차단 기본 false : 기존 세션만료 
		.expiredUrl("/expired"); //세션이 만료된 경우 이동 할 페이지
	}
	
}
