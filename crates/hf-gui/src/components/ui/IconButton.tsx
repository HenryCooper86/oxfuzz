import { forwardRef } from "react";

// The one icon-only button for the whole app. Uses the `.hf-action-btn` look
// (transparent border at rest -> subtle surface + border on hover; `.danger`
// -> red hover), so bare icon actions read as real, consistent buttons instead
// of floating boxes. Callers must pass `title` / `aria-label` for the label.
interface IconButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  /** Square size in px (default 28). */
  size?: number;
  /** Destructive affordance (red on hover). */
  danger?: boolean;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ size = 28, danger, className, style, type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={`hf-action-btn${danger ? " danger" : ""} ${className ?? ""}`}
      style={{ width: size, height: size, ...style }}
      {...props}
    />
  ),
);
IconButton.displayName = "IconButton";
