import { getConfig } from "@/config";
import styles from "./Disclaimer.module.css";

export function Disclaimer() {
  const config = getConfig();

  if (config.debug) {
    return (
      <div className={styles.banner}>
        <em>
          ⚠️ You are using a <strong>publicly accessible</strong> testing environment. Don't enter
          secrets into this system, especially not by reusing passwords for your user account.
        </em>
      </div>
    );
  }

  if (config.showDemoDisclaimer) {
    return (
      <div className={styles.banner}>
        <em>
          ⚠️ You are using a production deployment that is{" "}
          <strong>still only suitable for demo purposes.</strong> Any work done in this might be
          wiped later without notice.
        </em>
      </div>
    );
  }

  return null;
}
