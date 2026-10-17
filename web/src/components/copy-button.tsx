import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={() => {
        void navigator.clipboard?.writeText(value).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      {copied ? <Check /> : <Copy />}
      {copied ? "Copied" : label}
    </Button>
  );
}

/** CodeBlock shows a command with a copy button. */
export function CodeBlock({ value, label }: { value: string; label?: string }) {
  return (
    <div className="space-y-2">
      <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
        {value}
      </pre>
      <CopyButton value={value} label={label} />
    </div>
  );
}
