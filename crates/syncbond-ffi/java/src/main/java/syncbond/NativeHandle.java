package syncbond;

import java.lang.ref.Cleaner;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongConsumer;

/**
 * One native handle with an explicit {@link #close()} and a {@link Cleaner}
 * backstop. The cleaner action references only the free function, the raw
 * handle and a local flag — never this object — so an un-closed handle is
 * freed when the owner becomes unreachable.
 */
final class NativeHandle {
    private static final Cleaner CLEANER = Cleaner.create();

    private final long handle;
    private final AtomicBoolean closed;
    private final Cleaner.Cleanable cleanable;

    NativeHandle(long handle, LongConsumer free) {
        if (handle == 0) {
            throw new SyncbondException(Native.ERR_INPUT, "null native handle");
        }
        this.handle = handle;
        AtomicBoolean closed = new AtomicBoolean();
        this.closed = closed;
        this.cleanable = CLEANER.register(this, () -> {
            if (closed.compareAndSet(false, true)) {
                free.accept(handle);
            }
        });
    }

    /** The raw handle, or throw when this handle was closed. */
    long get() {
        if (closed.get()) {
            throw new SyncbondException(Native.ERR_INPUT, "use of closed syncbond handle");
        }
        return handle;
    }

    void close() {
        cleanable.clean();
    }
}
