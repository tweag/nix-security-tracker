import { getConfig } from "@/config";
import styles from "./Footer.module.css";

function Revision() {
  const { production, revision } = getConfig();
  const shortRev = revision.slice(0, 8);

  if (production) {
    return (
      <a href={`https://github.com/NixOS/nix-security-tracker/commit/${revision}`}>{shortRev}</a>
    );
  }

  return <span>{shortRev} (development)</span>;
}

export function Footer() {
  return (
    <footer className={styles.footer}>
      <p>
        Nixpkgs security tracker is part of{" "}
        <a href="https://nixos.org/community/teams/security/">NixOS security infrastructure</a>.
      </p>
      <p>
        <a href="https://github.com/NixOS/nix-security-tracker">Source code</a>, running revision{" "}
        <Revision />
      </p>
    </footer>
  );
}
