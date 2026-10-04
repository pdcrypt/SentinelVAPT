import Link from "next/link";

export default function NotFound() {
  return (
    <div className="panel">
      <h1>Not found</h1>
      <p>
        That page or record does not exist. <Link href="/projects">Back to projects</Link>
      </p>
    </div>
  );
}
