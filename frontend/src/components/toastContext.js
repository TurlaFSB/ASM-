import { createContext, useContext } from "react";

export const ToastContext = createContext({ toast: () => {} });

// const { toast } = useToast();  toast("Saved"); toast("Could not save", "bad");
export const useToast = () => useContext(ToastContext);
