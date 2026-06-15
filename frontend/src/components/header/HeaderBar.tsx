import { AuthStatus } from "./AuthStatus";
import styles from "./HeaderBar.module.css";
import { Title } from "./Title";

export function HeaderBar() {
  return (
    <header className={styles.headerBar}>
      <Title />
      <AuthStatus />
    </header>
  );
}
