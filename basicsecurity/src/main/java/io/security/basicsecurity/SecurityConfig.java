package io.security.basicsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration 
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

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
	}
	
}
