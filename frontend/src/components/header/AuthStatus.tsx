import { LogInIcon, LogOutIcon, UserIcon } from "lucide-preact";
import { Link } from "wouter-preact";
import { LOGIN_URL, logout, useAuth } from "@/hooks/useAuth";
import styles from "./AuthStatus.module.css";

export function AuthStatus() {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <span>Loading...</span>;
  }

  if (!isAuthenticated || !user) {
    return (
      <div className="row gap-small centered">
        <LogInIcon />
        <a href={LOGIN_URL} className={styles.loginLink}>
          Login with GitHub
        </a>
      </div>
    );
  }

  return (
    <div className="row gap centered">
      <Link className="row gap-small centered" href="/ui-v2/user" title={user.username}>
        {user.avatar_url ? (
          <img src={user.avatar_url} alt="avatar" className={styles.avatar} />
        ) : (
          <UserIcon className={`${styles.avatar} ${styles.placeholder}`} />
        )}
      </Link>
      <button type="button" onClick={logout} className={styles.logoutButton} title="Logout">
        <LogOutIcon />
      </button>
    </div>
  );
}
