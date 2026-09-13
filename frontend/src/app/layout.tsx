import './globals.css';
import type { Metadata } from 'next';
import { AuthProvider } from '@/context/AuthContext';

export const dynamic = 'force-dynamic';

export const metadata: Metadata = {
  title: 'Ch3ck3r — Intelligent API Security Scanner',
  description: 'Advanced API Security Scanner with SAST, DevSecOps pipeline integration, and GitHub repository scanning for OWASP API Top 10 detection',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var theme = localStorage.getItem('ch3ck3r_theme');
                  var prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                  if (theme === 'dark' || (!theme && prefersDark)) {
                    document.documentElement.classList.add('dark');
                  }
                } catch(e) {}

                // Cookie consent banner
                try {
                  if (!localStorage.getItem('ch3ck3r_cookie_consent')) {
                    var d = document;
                    var banner = d.createElement('div');
                    banner.id = 'cookie-banner';
                    banner.innerHTML =
                      '<div class="cookie-text">This website uses cookies for security session management and analytics. By continuing, you accept our use of cookies. <a href="#">Learn more</a></div>' +
                      '<div class="cookie-actions">' +
                        '<button class="cookie-btn-decline" onclick="window.__ch3ck3r_cookie_decline()">Decline</button>' +
                        '<button class="cookie-btn-accept" onclick="window.__ch3ck3r_cookie_accept()">Accept All</button>' +
                      '</div>';
                    d.body.appendChild(banner);

                    window.__ch3ck3r_cookie_accept = function() {
                      localStorage.setItem('ch3ck3r_cookie_consent', 'accepted');
                      banner.classList.add('cookie-hidden');
                    };
                    window.__ch3ck3r_cookie_decline = function() {
                      localStorage.setItem('ch3ck3r_cookie_consent', 'declined');
                      banner.classList.add('cookie-hidden');
                    };
                  }
                } catch(e) {}
              })();
            `,
          }}
        />
      </head>
      <body className="antialiased min-h-screen">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
