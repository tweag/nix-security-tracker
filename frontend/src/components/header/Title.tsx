import { Link } from "wouter-preact";
import styles from "./Title.module.css";

export function Title() {
  return (
    <h1 className={styles.title}>
      <Link href="/ui-v2/" className={styles.link}>
        <img
          src="/static/nixos-logomark-white-flat-none.svg"
          alt=""
          aria-hidden="true"
          className={styles.logo}
        />
        Nixpkgs security tracker
      </Link>
    </h1>
  );
}
