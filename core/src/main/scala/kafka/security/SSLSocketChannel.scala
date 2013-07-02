/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kafka.security

import java.io.IOException
import java.net._
import java.nio.ByteBuffer
import java.nio.channels._
import java.nio.channels.spi.SelectorProvider
import javax.net.ssl._
import javax.net.ssl.SSLEngineResult._
import java.util.concurrent._
import java.util.concurrent.atomic.AtomicInteger
import kafka.utils.Logging

object SSLSocketChannel {

  /**
   * Convenient client socket channel factory method
   * @param sch - underlying SocketChannel to wrap
   * @param host optional for SSL session reuse
   * @param port optional for SSL session resue
   * @return new SSLSocketChannel
   * @throws NoSuchAlgorithmException
   * @throws IOException
   */
  def makeSecureClientConnection(sch: SocketChannel, host: String, port: Int) = {
    // Pass host and port and try to use SSL session reuse as much as possible
    val engine = SSLContext.getDefault.createSSLEngine()
    engine.setEnabledProtocols(Array("SSLv3"));
    engine.setUseClientMode(true)
    new SSLSocketChannel(sch, engine)
  }
  
  /**
   * Convenient server socket channel factory method
   * 
   * @param sch - underlying SocketChannel to wrap
   * @return
   * @throws NoSuchAlgorithmException
   * @throws IOException
   */
  def makeSecureServerConnection(
  	sch: SocketChannel,
  	wantClientAuth: Boolean = true,
  	needClientAuth: Boolean = true) = {
    val engine = sch.socket.getRemoteSocketAddress match {
      case ise: InetSocketAddress =>
        SSLContext.getDefault.createSSLEngine(ise.getHostName, ise.getPort)
      case _ =>
        SSLContext.getDefault.createSSLEngine()
    }
    engine.setEnabledProtocols(Array("SSLv3"));
    engine.setUseClientMode(false)
    if (wantClientAuth) {
      engine.setWantClientAuth(true)
    }
    if (needClientAuth) {
      engine.setNeedClientAuth(true)
    }
    new SSLSocketChannel(sch, engine)
  }
  
  /**
   * This is for simulating slow networks. For production this should be set to false
   */
  val simulateSlowNetwork = false
  
  val runningTasks = -2
  private[this] lazy val counter = new AtomicInteger(0)
  private[kafka] lazy val executor = new ThreadPoolExecutor(2, 10,
                                      60L, TimeUnit.SECONDS,
                                      new SynchronousQueue[Runnable](),
                                      new ThreadFactory() {
    override def newThread(r: Runnable): Thread = {
      val thread = new Thread(r, "SSLSession-Task-Thread-%d".format(counter.incrementAndGet()))
      thread.setDaemon(true)
      thread
    }
  })
}


/**
 * An SSL based socket channel implemented based on JSSE doc
 * http://download.java.net/jdk8/docs/technotes/guides/security/jsse/JSSERefGuide.html
 */
class SSLSocketChannel(val underlying: SocketChannel, val sslEngine: SSLEngine)
  extends SocketChannel(underlying.provider) with Logging {
  import SSLSocketChannel.executor

  private[this] class SSLTasker(
    val runnable: Runnable
  ) extends Runnable {
  
    selectionKey.interestOps(0)
  
    override def run(): Unit = {
      try {
        runnable.run()
        outer.synchronized {
          handshakeStatus = sslEngine.getHandshakeStatus
          handshakeStatus match {
            case HandshakeStatus.NEED_WRAP =>
              debug("sslTasker setting up to write for %s".format(underlying.socket.getRemoteSocketAddress))
              selectionKey.interestOps(SelectionKey.OP_WRITE)
            case HandshakeStatus.NEED_UNWRAP =>
              // If socket data has already been read into buffer we have to consume it here
              if (peerNetData.position > 0) {
                debug("sslTasker found existing data %s. running hanshake for %s".format(peerNetData, underlying.socket.getRemoteSocketAddress))
                val init = outer.handshake(SelectionKey.OP_READ, selectionKey)
                if (init == 0) {
                  // when handshake is complete go back to read mode
                  debug("sslTasker setting up to read after hanshake")
                  selectionKey.interestOps(SelectionKey.OP_READ)
                } else if (init != SSLSocketChannel.runningTasks) {
                  debug("sslTasker setting up for operation %d after hanshake for %s".format(init, underlying.socket.getRemoteSocketAddress))                  
                  selectionKey.interestOps(init)
                }
              } else {
                debug("sslTasker setting up to read for %s".format(underlying.socket.getRemoteSocketAddress))
                selectionKey.interestOps(SelectionKey.OP_READ)
              }
            case HandshakeStatus.NEED_TASK =>
              val runnable = sslEngine.getDelegatedTask
              if (runnable != null) {
                debug("sslTasker running next task for %s".format(underlying.socket.getRemoteSocketAddress))
                executor.execute(new SSLTasker(runnable))
                handshakeStatus = null
              }
              return
            case _ =>
              throw new SSLException("unexpected handshakeStatus: " + handshakeStatus)              
          }
          selectionKey.selector.wakeup()
        }
      } catch {
        case t: Throwable =>
          error("Unexpected exception", t)
      }
    }
  }

  private[this] val outer = this
  
  /**
   * The engine handshake status.
   */
  @volatile private[this] var handshakeStatus: HandshakeStatus = HandshakeStatus.NOT_HANDSHAKING

  /**
   * The initial handshake ops.
   */
  private[this] var initialized = -1

  /**
   * Marker for shutdown status
   */
  private[this] var shutdown = false
 
  private[this] var peerAppData = ByteBuffer.allocate(sslEngine.getSession.getApplicationBufferSize)
  private[this] var myNetData = ByteBuffer.allocate(sslEngine.getSession.getPacketBufferSize)
  private[this] var peerNetData = ByteBuffer.allocate(sslEngine.getSession.getPacketBufferSize)
  private[this] val emptyBuffer = ByteBuffer.allocate(0)
  
  // Set initial values.
  myNetData.limit(0)
  
  // This needs to match blocking flag and needs to be false
  underlying.configureBlocking(false)

  /**
   * Simulate blocking with non-blocking underlying sockets. If the underlying socket
   * is made blocking then it is difficult to make blocking reads of known expected
   * length since the encrypted length is not known. So, we basically continue a
   *  non-blocking read of unexpected length and decrypt until the expected decrypted
   *  length is reached
   */
  private[this] var blocking = false
  
  @volatile private[this] var selectionKey: SelectionKey = null

  def simulateBlocking(b: Boolean) = { blocking = b }

  def socket(): Socket = underlying.socket

  def isConnected(): Boolean = underlying.isConnected

  def isConnectionPending(): Boolean = underlying.isConnectionPending

  def connect(remote: SocketAddress): Boolean = {
    val ret = underlying.connect(remote)
    if (blocking) {
      while (!finishConnect()) {
        try { 
          Thread.sleep(10)
    	} catch { 
    	  case _: InterruptedException =>
    	}
      }
      handshakeInBlockMode(SelectionKey.OP_WRITE)
      true
    } else ret
  }

  def finishConnect(): Boolean = underlying.finishConnect()

  def isReadable = finished && peerAppData.position > 0
    
  def read(dst: ByteBuffer): Int = {
    this.synchronized {
      // If there is data available just return it
      if (peerAppData.position >= dst.remaining) {
        return readFromPeerData(dst)
      } else if (underlying.socket.isInputShutdown) {
        throw new ClosedChannelException
      } else if (initialized != 0) {
        handshake(SelectionKey.OP_READ, selectionKey)
        return 0
      } else if (shutdown) {
        shutdown()
        return -1
      } else if (sslEngine.isInboundDone) {
        return -1
      } else {
        val count = readRaw()
        if (count <= 0) return count.asInstanceOf[Int]
      }

      // Process incoming data 
      if (unwrap() < 0) return -1
  
      readFromPeerData(dst)
    }
  }

  def read(dsts: Array[ByteBuffer], offset: Int, length: Int): Long = {
    var n = 0
    var i = offset
    def localReadLoop() {
      while (i < length) {
        if (dsts(i).hasRemaining) {
          val x = read(dsts(i))
          if (x > 0) {
            n += x
            if (!dsts(i).hasRemaining) {
              return
            }
          } else {
            if ((x < 0) && (n == 0)) {
              n = -1
            }
            return
          }
        }
        i = i + 1
      }
    }
    localReadLoop()
    n
  }

  def write(src: ByteBuffer): Int = {
    this.synchronized {
      if (myNetData.hasRemaining) {
        writeRaw(myNetData)
        return 0
      } else if (underlying.socket.isOutputShutdown) {
        throw new ClosedChannelException
      } else if (initialized != 0) {
        handshake(SelectionKey.OP_WRITE, selectionKey)
        return 0
      } else if (shutdown) {
        shutdown()
        return -1
      }
  
      // Wrap data before writing it out
      val written = wrap(src)
      
      // Write the data out now
      while (myNetData.hasRemaining)
        writeRaw(myNetData)
      written
    }
  }

  def write(srcs: Array[ByteBuffer], offset: Int, length: Int): Long = {
    var n = 0
    var i = offset
    def localWriteLoop {
      while (i < length) {
        if (srcs(i).hasRemaining) {
          var x = write(srcs(i))
          if (x > 0) {
            n += x
            if (!srcs(i).hasRemaining) {
              return
            }
          } else {
            return
          }
        }
        i = i + 1
      }
    }
    localWriteLoop
    n
  }

  /**
   * Is SSL handshake complete
   * 
   * @return true if SSL handshake complete, false otherwise
   */
  def finished(): Boolean = initialized == 0

  override def toString = "SSLSocketChannel[" + underlying.toString + "]"
      
  protected def implCloseSelectableChannel(): Unit = {
    try {
      // Use the non-locking version to avoid deadlock
      _shutdown()
    } catch {
      case x: Exception =>
    }
    underlying.close()
  }

  protected def implConfigureBlocking(block: Boolean): Unit = {
    simulateBlocking(block)
    // We never allow the actual channel to go to block mode
    if (!block) underlying.configureBlocking(block)
  }
  
  /**
   * SSL Handshake
   * 
   * @param SelectionKey mode o
   * @param SelectionKey key
   * @return final SelectionKey mode
   */
  def handshake(o: Int, key: SelectionKey): Int = {
    /**
     * @return true if more data is expected to be written
     */
    def writeIfReadyAndNeeded(mustWrite: Boolean): Boolean = {
      // Send handshake data to peer
      if ((o & SelectionKey.OP_WRITE) != 0) {
        writeRaw(myNetData)
        myNetData.remaining > 0
      } else mustWrite
    }
    /**
     * @return true if more data is expected to be read
     */
    def readIfReadyAndNeeded(mustRead: Boolean): Boolean = {
      // Read handshake data from peer
      if ((o & SelectionKey.OP_READ) != 0) {
        if (readRaw() < 0) {
          shutdown = true
          // Handle closed channel
          underlying.close()
          return true
        }
        // Process incoming handshaking data
        val oldPos = peerNetData.position
        unwrap()
        // Return true if no data has been unwrapped. We need to read more data in that case.
        oldPos == peerNetData.position       
      } else mustRead
    }
    /**
     * @return initialized state
     */
    def localHandshake(): Int = {
      while (true) {
        handshakeStatus match {
          case HandshakeStatus.NOT_HANDSHAKING =>
            // Begin handshake
            info("begin ssl handshake for %s".format(underlying.socket.getRemoteSocketAddress))
            sslEngine.beginHandshake()
            handshakeStatus = sslEngine.getHandshakeStatus
          case HandshakeStatus.NEED_UNWRAP =>
            debug("need unwrap in ssl handshake for %s".format(underlying.socket.getRemoteSocketAddress))
            if (readIfReadyAndNeeded(true)) {
              debug("select to read more for %s".format(underlying.socket.getRemoteSocketAddress))
              return SelectionKey.OP_READ
            }
          case HandshakeStatus.NEED_WRAP =>
            // Generate handshaking data
            debug("need wrap in ssl handshake for %s".format(underlying.socket.getRemoteSocketAddress))
            if (myNetData.remaining == 0) {
              wrap(emptyBuffer)
            }
            // Write handshake data if socket is ready or go back to select loop to write more later
            if (writeIfReadyAndNeeded(true)) {
              debug("select to write more for %s".format(underlying.socket.getRemoteSocketAddress))
              return SelectionKey.OP_WRITE
            }
          case HandshakeStatus.NEED_TASK =>
            handshakeStatus = runTasks()
          case HandshakeStatus.FINISHED =>
            info("finished ssl handshake for %s".format(underlying.socket.getRemoteSocketAddress))
            return 0
          case null =>
            return SSLSocketChannel.runningTasks
        }
      }
      o
    }

    this.synchronized {
      if (initialized == 0) return initialized

      if (selectionKey == null) selectionKey = key
      
      if (initialized != -1) {
        // Send handshake data in buffer to peer and return if data not fully written
        if (writeIfReadyAndNeeded(false)) return o
      }
      val init  = localHandshake()
      if (init != SSLSocketChannel.runningTasks) {
        initialized = init
      }
      init
    }
  }

  /**
   * Shutdown using locking
   * 
   */
  def shutdown() {
    this.synchronized(_shutdown())
    
    // Close transport
    underlying.close()
  }
 
  /**
   * Shutdown the socket by doing graceful SSL shutdown sequence. No locking is done as it creates deadlocks
   * when shutting down the server.
   * 
   */
  private def _shutdown() {
    shutdown = true
    
    // Indicate that application is done with engine
    if (!sslEngine.isOutboundDone) sslEngine.closeOutbound()

    myNetData.compact()
    while (!sslEngine.isOutboundDone()) {
      // Get close message and check res statuses
      val res = sslEngine.wrap(emptyBuffer, myNetData)
      if (res.getStatus != Status.CLOSED) {
        throw new SSLException("Unexpected shutdown status '" + res.getStatus + '\'')
      }
      
      // Send close message to peer
      myNetData.flip()
      try {
        while (myNetData.hasRemaining)
          writeRaw(myNetData)
      } catch {
        case ie: IOException => // Ignore write errors on shutdown
      }
    }
  }
  
  /*
   * Complete handshake in a simulated blocking mode
   * 
   * @param SelectionKey mode
   * @return final SelectionKey mode
   */
  private def handshakeInBlockMode(ops: Int) = {
    var o = ops
    while (o != 0) {
  	  val tops = handshake(o, null)
      if (tops == o) {
          try { 
            Thread.sleep(10)
      	  } catch { 
      	    case _: InterruptedException =>
      	  }
      } else {
        o = tops
      }
  	}
  	o
  }

  /**
   * Read data into peerNetData buffer from underlying channel
   * 
   * @return the number of read bytes.
   * @throws IOException on I/O errors.
   */
  private[this] def readRaw(): Long = {
    this.synchronized {
      try {
        val n = underlying.read(peerNetData)
        if (n < 0) {
          // EOF reached.
          sslEngine.closeInbound()
        }
        n
      } catch {
        case x: IOException =>
          sslEngine.closeInbound()
          throw x
      }
    }
  }

  /**
   * Decrypt data from peerNetData buffer and place into peerAppData buffer
   * 
   * @return amount of application level data decrypted
   * @throws IOException on I/O errors.
   */
  private[this] def unwrap(): Int = {
    val pos = peerAppData.position
    peerNetData.flip()
    trace("unwrap: flipped peerNetData %s for %s".format(peerNetData, underlying.socket.getRemoteSocketAddress))
    try {
      while (peerNetData.hasRemaining) {
        val result = sslEngine.unwrap(peerNetData, peerAppData)
        handshakeStatus = result.getHandshakeStatus
        result.getStatus match {
          case SSLEngineResult.Status.OK =>
            // Continue to read more until done
            if (handshakeStatus == HandshakeStatus.NEED_TASK) {
              handshakeStatus = runTasks()
              if (handshakeStatus == null) return 0
            }
          case SSLEngineResult.Status.BUFFER_OVERFLOW =>
            // Maybe need to enlarge the peer application data buffer or compact it.
            peerAppData = expand(peerAppData, sslEngine.getSession.getApplicationBufferSize)
            // retry the operation
          case SSLEngineResult.Status.BUFFER_UNDERFLOW =>
            // Not enough data. Come back later
            return 0
          case SSLEngineResult.Status.CLOSED =>
            // If there is unread data simply mark the connection shutdown, let it close after all data is read
            if (peerAppData.position == 0) {
              trace("uwrap: shutdown for %s".format(peerAppData, underlying.socket.getRemoteSocketAddress))
              shutdown()
              return -1
            } else {
              trace("uwrap: shutdown with non-empty peerAppData %s for %s".format(peerAppData, underlying.socket.getRemoteSocketAddress))
              shutdown = true
              return 0
            }
          case _ =>
            // This state is unexpected
            throw new SSLException("Unexpected state!")
        }
      }
    } finally {
      peerNetData.compact()
      trace("unwrap: compacted peerNetData %s for %s".format(peerNetData, underlying.socket.getRemoteSocketAddress))
    }
    peerAppData.position - pos
  }
  
  /**
   * Encrypt the data
   * 
   * @param src 
   * @return amount of data wrapped - typically the same size as the src data
   * @throws IOException on I/O errors.
   */
  private[this] def wrap(src: ByteBuffer): Int = {
    val written = src.remaining
    myNetData.compact()
    trace("wrap: compacted myNetData %s for %s".format(myNetData, underlying.socket.getRemoteSocketAddress))
    try {
      do {
        // Generate SSL/TLS encoded data (handshake or application data)
        val result = sslEngine.wrap(src, myNetData)
        handshakeStatus = result.getHandshakeStatus
        result.getStatus match {
          case SSLEngineResult.Status.OK =>
            // Nothing to do, src whould not have any data remaining
            if (handshakeStatus == HandshakeStatus.NEED_TASK) {
              handshakeStatus = runTasks()
              if (handshakeStatus == null) return 0
            }
          case SSLEngineResult.Status.BUFFER_OVERFLOW =>
            // Expand myNetData
            val size = if (src.remaining * 2 > sslEngine.getSession.getApplicationBufferSize) src.remaining * 2
              else sslEngine.getSession.getApplicationBufferSize
            myNetData = expand(myNetData, size)
          case SSLEngineResult.Status.CLOSED =>
            shutdown()
            throw new IOException("Write error received Status.CLOSED")
          case _ =>
            // This state is unexpected
            throw new SSLException("Unexpected state!")
        }
      } while (src.hasRemaining())
    } finally {
      myNetData.flip()
      trace("wrap: flipped myNetData %s for %s".format(myNetData, underlying.socket.getRemoteSocketAddress))
    }
    written
  }
  
  /**
   * Writes specified buffer to underlying socket channel
   * 
   * @param out the buffer.
   * @return the number of written bytes.
   * @throws IOException on I/O errors.
   */
  private[this] def writeRaw(out: ByteBuffer):Long = {
    /**
     * Simulate slow network by writing two bytes at a time
     */
    def writeTwo(i: ByteBuffer): ByteBuffer = {
      //if (blocking) return i
      val o = ByteBuffer.allocate(2)
      var rem = i.limit - i.position
      if (rem > o.capacity) rem = o.capacity
      var c = 0
      while (c < rem) {
        o.put(i.get)
        c += 1
      }
      o.flip()
      o
    }
    try {
        // Flush only if bytes available.
        if (out.hasRemaining) {
          underlying.write(if (SSLSocketChannel.simulateSlowNetwork) writeTwo(out) else out)
        } else 0
    } catch {
      case x: IOException =>
        // Can't write more bytes...
        sslEngine.closeOutbound()
        shutdown = true
        throw x
    }
  }
  
  /**
   * Runs delegated handshaking tasks synchronously for blocking and
   * asynchronously for non-blocking
   * 
   * @return the handshake status or null
   */
  private[this] def runTasks(): HandshakeStatus = {
    var runnable: Runnable = sslEngine.getDelegatedTask
    if (!blocking && selectionKey != null) {
      debug("runTasks asynchronously in ssl handshake for %s".format(underlying.socket.getRemoteSocketAddress))
      if (runnable != null) {
        executor.execute(new SSLTasker(runnable))
      }
      null
    } else {
      debug("runTasks synchronously in ssl handshake for %s".format(underlying.socket.getRemoteSocketAddress))
      while (runnable != null) {
        runnable.run()
        runnable = sslEngine.getDelegatedTask
      }
      sslEngine.getHandshakeStatus
    }
  }

  /**
   * Expands the specified buffer to ensure requested space
   * 
   * @param src the source buffer.
   * @param ensureSize
   * @return a new ByteBuffer if needed 
   */
  private[this] def expand(src: ByteBuffer, ensureSize: Int): ByteBuffer = {
    if (src.remaining < ensureSize) {
      // enlarge the peer application data buffer
      val newBuffer = ByteBuffer.allocate(src.capacity + ensureSize)
      if (src.position > 0) {
        // If old buffer had data copy it back into new
        src.flip()
        newBuffer.put(src)
      }
      newBuffer
    } else {
      src
    }
  }

  /**
   * Copy data from peerAppData to dest
   * 
   * @param dest - is the destination buffer to copy data into
   * @return number of bytes copied
   */
  private[this] def readFromPeerData(dest: ByteBuffer): Int = {
    peerAppData.flip()
    try {
      var n = peerAppData.remaining
      if (n > 0) {
        if (n > dest.remaining) {
          n = dest.remaining
        }
        var i = 0
        while (i < n) {
          dest.put(peerAppData.get)
          i = i+1
        }
      }
      n
    } finally {
      peerAppData.compact()
    }
  }
}
